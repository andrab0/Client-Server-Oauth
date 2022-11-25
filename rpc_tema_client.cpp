#include "rpc_tema_client.hpp"

#define PROTOCOL "tcp"
#define HOST "localhost"


int main(int argc, char const *argv[])
{
    CLIENT *handle;
    /* Structuri necesare pentru request_authorization */
    req_auth_param reqAuthParam;
    req_auth_resp *reqAuthResp;
    /* Structuri necesare pentru approve_request_token  */
    app_req_param approveReqParam;
    app_req_resp *approveReqResp;
    /* Structuri necesare pentru request_access_token */
    req_acc_token_param reqAccessTokenParam;
    req_acc_token_resp *reqAccessTokenResp;
    /* Structuri necesare pentru validate_delegated_action */
    val_del_act_param validDelActParam;
    val_del_act_resp *validDelActResp;

    /* Verific daca am primit fisier de input */
    if (argc != 2) {
        cout<<"Folosire: ./client <OP_FILE>"<<endl;
		return -1;
	}

    /* Creez handler-ul pentru client */
    handle = clnt_create(HOST, RPC_TEMA_PROG, RPC_TEMA_VERS, PROTOCOL);
    if(!handle) {
        perror("Failed to create client handle");
        clnt_pcreateerror(argv[0]);
        exit(1);
    }

    ifstream opFile(argv[1]);
    /* Verific daca fisierul meu s-a deschis ok */
    if(!opFile.is_open())
    {
        cout<<"Eroare la deschiderea fisierului de operatii!"<<endl;
        return -1;
    }

    /* Citesc linie cu linie din fisierul de operatii */
    while(!opFile.eof())
    {
        string line;
        getline(opFile, line);
        lines.push_back(line);
    }

    for(long unsigned int i = 0; i < lines.size(); i++)
    {
        /* Extrag id-ul utilizatorului */
        const string userId = lines[i].substr(0, 15);
        usersAndAccessTokens.insert(pair<string, string>(userId, tokenTemp));

        /* Extrag tipul operatiei */
        const string operation = lines[i].substr(16, lines[i].find(",", 16) - 16);
        if (operation == "REQUEST")
        {
            /* Extrag daca este necesar refresh-ul token-ului de acces */
            const char isRefreshAvaliable = lines[i].at(lines[i].size() - 1);

            /* Apelez procedura de request_authorization */
            reqAuthParam.id_clnt = (char*)userId.c_str();
            reqAuthResp = request_authorization_1(&reqAuthParam, handle);
            approveReqParam.token_rers = strdup(reqAuthResp->token_resp);

            /* Semnez tokenul si atasez permisiuni */
            if (strcmp(reqAuthResp->token_resp, "USER_NOT_FOUND") != 0)
            {
                /* Apelez procedura de approve_request_token */
                approveReqResp = approve_request_token_1(&approveReqParam, handle);

                /* Apelez procedura de request_authorization */
                const bool isRefreshNeeded = (isRefreshAvaliable == '1');
                if(!isRefreshNeeded)
                {
                    reqAccessTokenParam.id_clnt = (char*)userId.c_str();
                    reqAccessTokenParam.token = strdup(approveReqResp->token_perm);
                    reqAccessTokenResp = request_access_token_1(&reqAccessTokenParam, handle);
                }
                else
                {
                    /* Daca am nevoie de token de refresh, modific id-ul user-ului adaugand 1 la final */
                    const string userIdTemp = userId + isRefreshAvaliable;
                    reqAccessTokenParam.id_clnt = (char*)userIdTemp.c_str();
                    reqAccessTokenParam.token = strdup(approveReqResp->token_perm);
                    reqAccessTokenResp = request_access_token_1(&reqAccessTokenParam, handle);
                }

                if (strcmp(reqAccessTokenResp->token_rers, "REQUEST_DENIED") == 0)
                {
                    cout<<"REQUEST_DENIED"<<endl;
                }
                else
                {
                    usersAndAccessTokens.at(userId) = reqAccessTokenResp->token_rers;
                    cout<<approveReqResp->token_perm<<" -> "<<reqAccessTokenResp->token_rers;
                    if (isRefreshNeeded)
                    {
                        cout<<","<<reqAccessTokenResp->token_regen<<endl;
                    }
                    else
                    {
                        cout<<endl;
                    }
                }
            }
            else
            {
                cout<<"USER_NOT_FOUND"<<endl;
            }
        }

        if (operation != "REQUEST")
        {
            /* Preiau resursa pe care vreau sa aplic operatia */
            const string resource = lines[i].substr(lines[i].find(",", 16) + 1, lines[i].size());
            validDelActParam.tip_op = (char*)operation.c_str();
            validDelActParam.resursa = (char*)resource.c_str();
            validDelActParam.token_rers = (char*)usersAndAccessTokens.at(userId).c_str();
            /* Apelez procedura de validate_delegated_action */
            validDelActResp = validate_delegated_action_1(&validDelActParam, handle);
            cout<<validDelActResp->mesaj<<endl;

            if (validDelActResp->new_acc_token != usersAndAccessTokens.at(userId))
            {
                usersAndAccessTokens.at(userId) = validDelActResp->new_acc_token;
            }
        }
    }

    /* Inchid fisierul deschis */
    opFile.close();
    /* Eliberez memoria folosita */
    clnt_destroy(handle);
    fflush(stdout);
    return 0;
}