#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <net/cfg80211.h>
#include <net/netlink.h>

#include <brcmu_utils.h>
#include <defs.h>
#include <brcmu_wifi.h>
#include "core.h"
#include "debug.h"
#include "tracepoint.h"
#include "fwil_types.h"
#include "p2p.h"
#include "btcoex.h"
#include "cfg80211.h"
#include "feature.h"
#include "fwil.h"
#include "proto.h"
#include "vendor.h"
#include "bus.h"
#include "common.h"

const struct brcmf_tlv *
brcmf_parse_tlvs(const void *buf, int buflen, uint key)
{
	const struct brcmf_tlv *elt = buf;
	int totlen = buflen;

	/* find tagged parameter */
	while (totlen >= TLV_HDR_LEN) {
		int len = elt->len;

		/* validate remaining totlen */
		if ((elt->id == key) && (totlen >= (len + TLV_HDR_LEN)))
			return elt;

		elt = (struct brcmf_tlv *)((u8 *)elt + (len + TLV_HDR_LEN));
		totlen -= (len + TLV_HDR_LEN);
	}

	return NULL;
}

static s32
brcmf_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *ndev,
		      struct cfg80211_ibss_params *params)
{
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;
	struct brcmf_join_params join_params;
	size_t join_params_size = 0;
	s32 err = 0;
	s32 wsec = 0;
	s32 bcnprd;
	u16 chanspec;
	u32 ssid_len;

	brcmf_dbg(TRACE, "Enter\n");
	if (!check_vif_up(ifp->vif))
		return -EIO;

	if (params->ssid)
		brcmf_dbg(CONN, "SSID: %s\n", params->ssid);
	else {
		brcmf_dbg(CONN, "SSID: NULL, Not supported\n");
		return -EOPNOTSUPP;
	}

	set_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

	if (params->bssid)
		brcmf_dbg(CONN, "BSSID: %pM\n", params->bssid);
	else
		brcmf_dbg(CONN, "No BSSID specified\n");

	if (params->chandef.chan)
		brcmf_dbg(CONN, "channel: %d\n",
			  params->chandef.chan->center_freq);
	else
		brcmf_dbg(CONN, "no channel specified\n");

	if (params->channel_fixed)
		brcmf_dbg(CONN, "fixed channel required\n");
	else
		brcmf_dbg(CONN, "no fixed channel required\n");

	if (params->ie && params->ie_len)
		brcmf_dbg(CONN, "ie len: %d\n", params->ie_len);
	else
		brcmf_dbg(CONN, "no ie specified\n");

	if (params->beacon_interval)
		brcmf_dbg(CONN, "beacon interval: %d\n",
			  params->beacon_interval);
	else
		brcmf_dbg(CONN, "no beacon interval specified\n");

	if (params->basic_rates)
		brcmf_dbg(CONN, "basic rates: %08X\n", params->basic_rates);
	else
		brcmf_dbg(CONN, "no basic rates specified\n");

	if (params->privacy)
		brcmf_dbg(CONN, "privacy required\n");
	else
		brcmf_dbg(CONN, "no privacy required\n");

	/* Configure Privacy for starter */
	if (params->privacy)
		wsec |= WEP_ENABLED;

	err = brcmf_fil_iovar_int_set(ifp, "wsec", wsec);
	if (err) {
		brcmf_err("wsec failed (%d)\n", err);
		goto done;
	}

	/* Configure Beacon Interval for starter */
	if (params->beacon_interval)
		bcnprd = params->beacon_interval;
	else
		bcnprd = 100;

	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BCNPRD, bcnprd);
	if (err) {
		brcmf_err("WLC_SET_BCNPRD failed (%d)\n", err);
		goto done;
	}

	/* Configure required join parameter */
	memset(&join_params, 0, sizeof(struct brcmf_join_params));

	/* SSID */
	ssid_len = min_t(u32, params->ssid_len, IEEE80211_MAX_SSID_LEN);
	memcpy(join_params.ssid_le.SSID, params->ssid, ssid_len);
	join_params.ssid_le.SSID_len = cpu_to_le32(ssid_len);
	join_params_size = sizeof(join_params.ssid_le);

	/* BSSID */
	if (params->bssid) {
		memcpy(join_params.params_le.bssid, params->bssid, ETH_ALEN);
		join_params_size += BRCMF_ASSOC_PARAMS_FIXED_SIZE;
		memcpy(profile->bssid, params->bssid, ETH_ALEN);
	} else {
		eth_broadcast_addr(join_params.params_le.bssid);
		eth_zero_addr(profile->bssid);
	}

	/* Channel */
	if (params->chandef.chan) {
		u32 target_channel;

		cfg->channel =
			ieee80211_frequency_to_channel(
				params->chandef.chan->center_freq);
		if (params->channel_fixed) {
			/* adding chanspec */
			chanspec = chandef_to_chanspec(&cfg->d11inf,
						       &params->chandef);
			join_params.params_le.chanspec_list[0] =
				cpu_to_le16(chanspec);
			join_params.params_le.chanspec_num = cpu_to_le32(1);
			join_params_size += sizeof(join_params.params_le);
		}

		/* set channel for starter */
		target_channel = cfg->channel;
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_CHANNEL,
					    target_channel);
		if (err) {
			brcmf_err("WLC_SET_CHANNEL failed (%d)\n", err);
			goto done;
		}
	} else
		cfg->channel = 0;

	cfg->ibss_starter = false;


	err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
				     &join_params, join_params_size);
	if (err) {
		brcmf_err("WLC_SET_SSID failed (%d)\n", err);
		goto done;
	}

done:
	if (err)
		clear_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);
	brcmf_dbg(TRACE, "Exit\n");
	return err;
}

static s32
brcmf_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *ndev,struct cfg80211_ap_settings *settings)
{
	s32 ie_offset;
	struct brcmf_cfg80211_info *cfg = wiphy_to_cfg(wiphy);
	struct brcmf_if *ifp = netdev_priv(ndev);
	const struct brcmf_tlv *ssid_ie;
	const struct brcmf_tlv *country_ie;
	struct brcmf_ssid_le ssid_le;
	s32 err = -EPERM;
	const struct brcmf_tlv *rsn_ie;
	const struct brcmf_vs_tlv *wpa_ie;
	struct brcmf_join_params join_params;
	enum nl80211_iftype dev_role;
	struct brcmf_fil_bss_enable_le bss_enable;
	u16 chanspec = chandef_to_chanspec(&cfg->d11inf, &settings->chandef);
	bool mbss;
	int is_11d;

	brcmf_dbg(TRACE, "ctrlchn=%d, center=%d, bw=%d, beacon_interval=%d, dtim_period=%d,\n",
		  settings->chandef.chan->hw_value,
		  settings->chandef.center_freq1, settings->chandef.width,
		  settings->beacon_interval, settings->dtim_period);
	brcmf_dbg(TRACE, "ssid=%s(%zu), auth_type=%d, inactivity_timeout=%d\n",
		  settings->ssid, settings->ssid_len, settings->auth_type,
		  settings->inactivity_timeout);
	dev_role = ifp->vif->wdev.iftype;
	mbss = ifp->vif->mbss;

	/* store current 11d setting */
	brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_REGULATORY, &ifp->vif->is_11d);
	country_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
				      settings->beacon.tail_len,
				      WLAN_EID_COUNTRY);
	is_11d = country_ie ? 1 : 0;

	memset(&ssid_le, 0, sizeof(ssid_le));
	if (settings->ssid == NULL || settings->ssid_len == 0) {
		ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
		ssid_ie = brcmf_parse_tlvs(
				(u8 *)&settings->beacon.head[ie_offset],
				settings->beacon.head_len - ie_offset,
				WLAN_EID_SSID);
		if (!ssid_ie)
		//#######################################################
		// if (!ssid_ie || ssid_ie->len > IEEE80211_MAX_SSID_LEN)
		//#######################################################
			return -EINVAL;

		memcpy(ssid_le.SSID, ssid_ie->data, ssid_ie->len);
		ssid_le.SSID_len = cpu_to_le32(ssid_ie->len);
		brcmf_dbg(TRACE, "SSID is (%s) in Head\n", ssid_le.SSID);
	} else {
		memcpy(ssid_le.SSID, settings->ssid, settings->ssid_len);
		ssid_le.SSID_len = cpu_to_le32((u32)settings->ssid_len);
	}

	if (!mbss) {
		brcmf_set_mpc(ifp, 0);
		brcmf_configure_arp_nd_offload(ifp, false);
	}

	/* find the RSN_IE */
	rsn_ie = brcmf_parse_tlvs((u8 *)settings->beacon.tail,
				  settings->beacon.tail_len, WLAN_EID_RSN);

	/* find the WPA_IE */
	wpa_ie = brcmf_find_wpaie((u8 *)settings->beacon.tail,
				  settings->beacon.tail_len);

	if ((wpa_ie != NULL || rsn_ie != NULL)) {
		brcmf_dbg(TRACE, "WPA(2) IE is found\n");
		if (wpa_ie != NULL) {
			/* WPA IE */
			err = brcmf_configure_wpaie(ifp, wpa_ie, false);
			if (err < 0)
				goto exit;
		} else {
			struct brcmf_vs_tlv *tmp_ie;

			tmp_ie = (struct brcmf_vs_tlv *)rsn_ie;

			/* RSN IE */
			err = brcmf_configure_wpaie(ifp, tmp_ie, true);
			if (err < 0)
				goto exit;
		}
	} else {
		brcmf_dbg(TRACE, "No WPA(2) IEs found\n");
		brcmf_configure_opensecurity(ifp);
	}

	brcmf_config_ap_mgmt_ie(ifp->vif, &settings->beacon);

	/* Parameters shared by all radio interfaces */
	if (!mbss) {
		if (is_11d != ifp->vif->is_11d) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_REGULATORY,
						    is_11d);
			if (err < 0) {
				brcmf_err("Regulatory Set Error, %d\n", err);
				goto exit;
			}
		}
		if (settings->beacon_interval) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BCNPRD,
						    settings->beacon_interval);
			if (err < 0) {
				brcmf_err("Beacon Interval Set Error, %d\n",
					  err);
				goto exit;
			}
		}
		if (settings->dtim_period) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_DTIMPRD,
						    settings->dtim_period);
			if (err < 0) {
				brcmf_err("DTIM Interval Set Error, %d\n", err);
				goto exit;
			}
		}

		if ((dev_role == NL80211_IFTYPE_AP) &&
		    ((ifp->ifidx == 0) ||
		     !brcmf_feat_is_enabled(ifp, BRCMF_FEAT_RSDB))) {
			err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_DOWN, 1);
			if (err < 0) {
				brcmf_err("BRCMF_C_DOWN error %d\n", err);
				goto exit;
			}
			brcmf_fil_iovar_int_set(ifp, "apsta", 0);
		}

		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, 1);
		if (err < 0) {
			brcmf_err("SET INFRA error %d\n", err);
			goto exit;
		}
	} else if (WARN_ON(is_11d != ifp->vif->is_11d)) {
		/* Multiple-BSS should use same 11d configuration */
		err = -EINVAL;
		goto exit;
	}

	/* Interface specific setup */
	if (dev_role == NL80211_IFTYPE_AP) {
		if ((brcmf_feat_is_enabled(ifp, BRCMF_FEAT_MBSS)) && (!mbss))
			brcmf_fil_iovar_int_set(ifp, "mbss", 1);

		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_AP, 1);
		if (err < 0) {
			brcmf_err("setting AP mode failed %d\n", err);
			goto exit;
		}
		if (!mbss) {
			/* Firmware 10.x requires setting channel after enabling
			 * AP and before bringing interface up.
			 */
			err = brcmf_fil_iovar_int_set(ifp, "chanspec", chanspec);
			if (err < 0) {
				brcmf_err("Set Channel failed: chspec=%d, %d\n",
					  chanspec, err);
				goto exit;
			}
		}
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 1);
		if (err < 0) {
			brcmf_err("BRCMF_C_UP error (%d)\n", err);
			goto exit;
		}
		/* On DOWN the firmware removes the WEP keys, reconfigure
		 * them if they were set.
		 */
		brcmf_cfg80211_reconfigure_wep(ifp);

		memset(&join_params, 0, sizeof(join_params));
		/* join parameters starts with ssid */
		memcpy(&join_params.ssid_le, &ssid_le, sizeof(ssid_le));
		/* create softap */
		err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID,
					     &join_params, sizeof(join_params));
		if (err < 0) {
			brcmf_err("SET SSID error (%d)\n", err);
			goto exit;
		}

		if (settings->hidden_ssid) {
			err = brcmf_fil_iovar_int_set(ifp, "closednet", 1);
			if (err) {
				brcmf_err("closednet error (%d)\n", err);
				goto exit;
			}
		}

		brcmf_dbg(TRACE, "AP mode configuration complete\n");
	} else if (dev_role == NL80211_IFTYPE_P2P_GO) {
		err = brcmf_fil_iovar_int_set(ifp, "chanspec", chanspec);
		if (err < 0) {
			brcmf_err("Set Channel failed: chspec=%d, %d\n",
				  chanspec, err);
			goto exit;
		}
		err = brcmf_fil_bsscfg_data_set(ifp, "ssid", &ssid_le,
						sizeof(ssid_le));
		if (err < 0) {
			brcmf_err("setting ssid failed %d\n", err);
			goto exit;
		}
		bss_enable.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
		bss_enable.enable = cpu_to_le32(1);
		err = brcmf_fil_iovar_data_set(ifp, "bss", &bss_enable,
					       sizeof(bss_enable));
		if (err < 0) {
			brcmf_err("bss_enable config failed %d\n", err);
			goto exit;
		}

		brcmf_dbg(TRACE, "GO mode configuration complete\n");
	} else {
		WARN_ON(1);
	}

	set_bit(BRCMF_VIF_STATUS_AP_CREATED, &ifp->vif->sme_state);
	brcmf_net_setcarrier(ifp, true);

exit:
	if ((err) && (!mbss)) {
		brcmf_set_mpc(ifp, 1);
		brcmf_configure_arp_nd_offload(ifp, true);
	}
	return err;
}