#include "rpc_tema_server.hpp"
#include "rpc_tema_svc.h"

req_auth_resp *request_authorization_1_svc(req_auth_param *data, struct svc_req *cl)
{
    static string user_id;
    static string user_token;
    static req_auth_resp *response = (req_auth_resp*)malloc(sizeof(req_auth_resp));

    /* Preiau id-ul userului trimis ca si parametru */
    user_id = data->id_clnt;
    // cout<<"User id: "<<user_id<<endl;

    /* Daca userul exista, generez un nou token pentru el si il adaug in map ca si valoare */
    cout<<"BEGIN "<<user_id<<" AUTHZ"<<endl;
    /* Verific daca acesta exista in map */
    const bool user_exists = check_if_user_exists(user_id);
    if (user_exists) 
    {
        /* Generez request token-ul */
        user_token = generate_access_token((char*)user_id.c_str());
        cout<<"  RequestToken = "<<user_token<<endl;
        users_and_req_tokens.at(user_id) = user_token;
    } 
    else if (!user_exists)
    {
        user_token = "USER_NOT_FOUND";
    }

    /* Setez raspunsul */
    response->token_resp = (char*)user_token.c_str();
    return response;
    
}

req_acc_token_resp *request_access_token_1_svc(req_acc_token_param *data, struct svc_req *cl)
{
    static string user_id;
    static string req_token;
    static string acc_token;
    static string ref_token;
    static req_acc_token_resp *response = (req_acc_token_resp*)malloc(sizeof(req_acc_token_resp));

    /* Preiau id-ul userului si token-ul de request trimis ca si parametru */
    user_id = data->id_clnt;
    req_token = data->token;

    /* Verific daca token-ul este semnat */
    // const bool isTokenSigned = token_and_status.at(req_token);

    // cout<<token_and_permisions.at(req_token)<<endl;
    // permisions.pop();
    if (token_and_permisions.at(req_token) == "*,-")
    {
        acc_token = "REQUEST_DENIED";
    }
    else
    // else if(token_and_permisions.at(req_token) != "*,-")
    {
        /* Generez acces token-ul */
        acc_token = generate_access_token((char*)req_token.c_str());
        // ref_token = generate_access_token((char*)acc_token.c_str());
        cout<<"  AccessToken = "<<acc_token<<endl;

        /* Adaug acces token-ul in map */   
        if (check_if_user_exists(user_id))
        {
            users_and_acc_tokens.at(user_id) = acc_token;
            // token_and_refresh.insert(pair<string, string>(acc_token, ref_token));   
        }
    }

    ref_token = token_temp;

    /* Setez raspunsul */
    response->token_rers = (char*)acc_token.c_str();
    response->token_regen = (char*)ref_token.c_str();
    response->per_valab = valid_time;

    token_and_counter.insert(pair<string, int>(acc_token, valid_time));

    return response;
};

val_del_act_resp *validate_delegated_action_1_svc(val_del_act_param *data, struct svc_req *cl)
{
    return NULL;
}
//     string tip_operatie;
//     string resursa;
//     string token_acc_rers;
//     string user_id;
//     static val_del_act_resp *response = (val_del_act_resp*)malloc(sizeof(val_del_act_resp));

//     /* Preiau tipul operatiei, resursa si token-ul de acces trimis ca si parametru */
//     user_id = data->id_clnt;
//     tip_operatie = data->tip_op;
//     resursa = data->resursa;
//     token_acc_rers = data->token_rers;

//     response->mesaj = "PERMISSION_GRANTED";

//     /* Verific daca token-ul este valid */
//     const string userToToken = get_user_for_token(token_acc_rers);

//     if(userToToken != user_id) {
//         response->mesaj = "PERMISSION_DENIED";
//     }
    
//     if(check_if_token_expired(token_acc_rers)) {
//         response->mesaj = "TOKEN_EXPIRED";
//     }

//     if(check_if_resource_exists(resursa)) {
//         response->mesaj = "RESOURCE_NOT_FOUND";
//     }

//     if(check_if_permision_exists(token_acc_rers, tip_operatie)) {
//         response->mesaj = "OPERATION_NOT_PERMITTED";
//     }

//     return response;
// };

app_req_resp *approve_request_token_1_svc(app_req_param *data, struct svc_req *cl)
{
    static string user_token;
    static app_req_resp *response = (app_req_resp*)malloc(sizeof(app_req_resp));

    /* Preiau tokenul trimis ca si parametru */
    user_token = data->token_rers;

    /* Marchez tokenul ca fiind semnat daca are permisiuni */
    const string currPermisions = permisions.front();
    token_and_permisions.insert(pair<string, string>(user_token, currPermisions));
    permisions.pop();

    // token_and_status.insert(pair<string, bool>(user_token, true));

    /* Setez raspunsul */
    response->token_perm = (char*)user_token.c_str();

    return response;
};


bool check_if_user_exists(const string user_id) 
{
    if ((users_and_req_tokens.find(user_id)) != (users_and_req_tokens.end())) {
        // cout<<"  User found"<<endl;
        return true;
    } 

    // cout<<"  User not found"<<endl;
    return false;
}

// string get_user_for_token(const string acc_token)
// {
//     for(auto &iterator : users_and_acc_tokens) {
//         if (iterator.second == acc_token) {
//             return iterator.first;
//         }
//     }
// }

// bool check_if_token_expired(const string acc_token)
// {
//     if (token_and_counter.at(acc_token) == 0) {
//         return true;
//     }

//     return false;
// }

// bool check_if_resource_exists(const string resource)
// {
//     for (auto &iterator : resource_and_permisions) {
//         if (iterator == resource) {
//             return true;
//         }
//     }

//     return false;
// }

// bool check_if_permision_exists(const string acc_token, const string permision)
// {
//     for (auto &iterator : token_and_permisions.at(acc_token)) {
//         if (iterator == permision) {
//             return true;
//         }
//     }

//     return false;
// }



int main (int argc, char **argv)
{
	register SVCXPRT *transp;

	pmap_unset (RPC_TEMA_PROG, RPC_TEMA_VERS);

    /* Verific daca am primit fisier de input */
    if (argc < 4) {
        cout<<"Folosire: ./server <CLIENTI_DB> <RESOURCES_DB> <APPROVALS_DB> *<TOKEN_PERIOD_FILE>"<<endl;
		return -1;
	}

    ifstream clientsFile(argv[1]);
    /* Verific daca fisierul meu s-a deschis ok */
    if(!clientsFile.is_open())
    {
        cout<<"Eroare la deschiderea fisierului de clienti!"<<endl;
        return -1;
    }
    /* Stochez id-urile clientilor intr-un map cu un token temporar*/
    int noClients;
    clientsFile>>noClients;
    for (int i = 0; i < noClients; i++) {
        string userId;
        clientsFile>>userId;
        /* Initializez map-urile pe care le voi folosi ulterior */
        users_and_req_tokens.insert(pair<string, string>(userId, token_temp));
        users_and_acc_tokens.insert(pair<string, string>(userId, token_temp));
    }
    clientsFile.close();

    ifstream resourcesFile(argv[2]);
    /* Verific daca fisierul meu s-a deschis ok */
    if(!resourcesFile.is_open())
    {
        cout<<"Eroare la deschiderea fisierului de resurse!"<<endl;
        return -1;
    }

    /* Stochez resursele intr-un vector */
    int noResources;
    resourcesFile>>noResources;
    for (int i = 0; i < noResources; i++) {
        string resource;
        resourcesFile>>resource;
        resources.push_back(resource);
    }
    resourcesFile.close();

    ifstream approvalsFile(argv[3]);
    /* Verific daca fisierul meu s-a deschis ok */
    if(!approvalsFile.is_open())
    {
        cout<<"Eroare la deschiderea fisierului de aprobari!"<<endl;
        return -1;
    }

    /* Stochez permisiunile intr-o coada */
    while(!approvalsFile.eof())
    {
        string permision;
        getline(approvalsFile, permision);
        permisions.push(permision);
    }
    approvalsFile.close();

    if(argv[4])
    {
        ifstream tokenAvailabilityFile(argv[4]);
        /* Verific daca fisierul meu s-a deschis ok */
        if(!tokenAvailabilityFile.is_open())
        {
            cout<<"Eroare la deschiderea fisierului de valabilitate a token-ului!"<<endl;
            return -1;
        }

        /* Stochez valabilitatea token-ului intr-o variabila */
        string line;
        getline(tokenAvailabilityFile, line);
        line = line[line.size() - 1];
        valid_time = stoi(line);

        tokenAvailabilityFile.close();
    }

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, RPC_TEMA_PROG, RPC_TEMA_VERS, rpc_tema_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (RPC_TEMA_PROG, RPC_TEMA_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, RPC_TEMA_PROG, RPC_TEMA_VERS, rpc_tema_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (RPC_TEMA_PROG, RPC_TEMA_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);


	/* NOTREACHED */
}
