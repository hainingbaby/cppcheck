void checkbufferoverflow()
{
    const SymbolDatabase *symboldatabase = mTokenizer->getSymbolDatabase();
    const Token *thirdparam = nullptr;
    for(const Scope * const scope : symboldatabase->functionScopes){
        for(const Token *tok = scope->bodyStart; tok != scope->bodyEnd; tok = tok->next()){
            // printf(tok->str().c_str());
            if(Token::Match(tok, "memcpy ( %any% , %any% ,")){
                thirdparam = tok->tokAt(6);
                // printf(thirdparam->str().c_str());
            }
            else if(Token::Match(tok, "memcpy ( %any% , %any% .|->|%op% %any% ,")){
                thirdparam = tok->tokAt(8);
                // printf(thirdparam->str().c_str());x
            }
            else if(Token::Match(tok, "memcpy ( %op% %any% [ %any% ] , %any% .|-> %any% ,")){
                thirdparam = tok->tokAt(12);
                // printf("find....\n");
            }
            else if(Token::Match(tok, "memcpy ( %op% %any% [ %any% ] , %any% ,")){
                thirdparam = tok->tokAt(10);
                // printf("find....\n");
            }
            else if(Token::Match(tok, "memcpy ( %any% .|-> %any% , %op% %any% [ %any% ] ,")){
                thirdparam = tok->tokAt(12);
                // printf("find....\n");
            }
            else if(Token::Match(tok, "memcpy ( %any% .|-> %any% , %any% ,")){
                thirdparam = tok->tokAt(8);
                // printf(thirdparam->str().c_str());
            }
            else if(Token::Match(tok, "memcpy ( %any% .|-> %any% , %any% .|-> %any% ,")){
                thirdparam = tok->tokAt(10);
                // printf(thirdparam->str().c_str());
            }
            else
                continue;

            if(thirdparam){

                int flag = 0;
                const unsigned int tpID = thirdparam->varId();
                if(tpID == 0U)
                    continue;
                for(const Token *atoken = thirdparam->tokAt(-150); atoken!=tok; atoken = atoken->next()){
                    if(Token::Match(atoken, "if|IRDA_ASSERT (")){
                        for(const Token *nowiftok = atoken->tokAt(1); nowiftok != atoken->next()->link(); nowiftok = nowiftok->next()){
                            if(Token::Match(nowiftok, " %any% <|<=|>|>=|== %varid%", tpID)||
                                Token::Match(nowiftok, " (|%oror% %varid% <|<=|>|>=|== %any%", tpID)||
                                Token::Match(nowiftok, " %varid% .|-> %any% <|<=|>|>=|== %any% ", tpID)||
                                Token::Match(nowiftok, " %varid% .|-> %any% %op% %any% <|<=|>|>=|== %any% ", tpID)){
                                flag = 1;
                                break;
                            }
                            else
                                continue;
                        }
                    }
                    else
                        continue;
                }
                if(!flag)
                    ThirdParamError(thirdparam, thirdparam->str());
            }
        }
    }
}