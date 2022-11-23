#include "rpc_tema_client.hpp"

#define PROTOCOL "tcp"
#define HOST "localhost"


int main(int argc, char const *argv[])
{
    CLIENT *handle;
    /* Structuri necesare pentru request_authorization */
    req_auth_param req_auth_param_1_arg;
    req_auth_resp *req_auth_1_arg_res;
    /* Structuri necesare pentru approve_request_token  */
    app_req_param app_req_param_1_arg;
    app_req_resp *app_req_resp_1_res;
    /* Structuri necesare pentru request_access_token */
    req_acc_token_param req_acc_token_param_1_arg;
    req_acc_token_resp *req_acc_token_resp_1_res;

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

    ifstream opfile(argv[1]);
    /* Verific daca fisierul meu s-a deschis ok */
    if(!opfile.is_open())
    {
        cout<<"Eroare la deschiderea fisierului de operatii!"<<endl;
        return -1;
    }

    /* Citesc linie cu linie din fisierul de operatii */
    while(!opfile.eof())
    {
        string line;
        getline(opfile, line);
        lines.push_back(line);
    }

    for(long unsigned int i = 0; i < lines.size(); i++)
    {
        /* extrag id-ul utilizatorului */
        const string user_id = lines[i].substr(0, 15);

        /* extrag tipul operatiei*/
        const string operation = lines[i].substr(16, lines[i].find(",", 16) - 16);
        if (operation == "REQUEST")
        {
            /* extrag daca este disponibil refresh-ul */
            const char isRefreshAvaliable = lines[i].at(lines[i].size() - 1);

            /* Apelez procedura de request_authorization*/
            req_auth_param_1_arg.id_clnt = (char*)user_id.c_str();
            req_auth_1_arg_res = request_authorization_1(&req_auth_param_1_arg, handle);
            app_req_param_1_arg.token_rers = strdup(req_auth_1_arg_res->token_resp);

            /* Semnez tokenul si atasez permisiuni */
            if (strcmp(req_auth_1_arg_res->token_resp, "USER_NOT_FOUND") != 0)
            {
                /* Apelez procedura de approve_request_token */
                app_req_resp_1_res = approve_request_token_1(&app_req_param_1_arg, handle);

                /* Apelez procedura de request_authorization */
                req_acc_token_param_1_arg.id_clnt = (char*)user_id.c_str();
                req_acc_token_param_1_arg.token = strdup(app_req_resp_1_res->token_perm);
                req_acc_token_resp_1_res = request_access_token_1(&req_acc_token_param_1_arg, handle);

                if (strcmp(req_acc_token_resp_1_res->token_rers, "REQUEST_DENIED") == 0)
                {
                    cout<<"REQUEST_DENIED"<<endl;
                }
                else
                {
                    cout<<app_req_resp_1_res->token_perm<<" -> "<<req_acc_token_resp_1_res->token_rers<<endl;
                }
            }
            else
            {
                cout<<"USER_NOT_FOUND"<<endl;
            }
        }

        if (operation != "REQUEST")
        {
            /* preiau resursa pe care vreau sa aplic operatia */
            const string resource = lines[i].substr(lines[i].find(",", 16) + 1, lines[i].size());
        }
    }

    /* Inchid fisierul deschis */ 
    opfile.close();
    return 0;
}