#include "rpc_tema_server.hpp"

req_auth_resp *request_authorization_1_svc(req_auth_param *data, struct svc_req *cl)
{
    static string userId;
    static string requestToken;
    static req_auth_resp *response = (req_auth_resp*)malloc(sizeof(req_auth_resp));

    /* Preiau id-ul userului trimis ca si parametru */
    userId = data->id_clnt;

    /* Daca userul exista, generez un nou token pentru el si il adaug in map ca si valoare */
    cout<<"BEGIN "<<userId<<" AUTHZ"<<endl;
    /* Verific daca acesta exista in map */
    const bool isExistingUser = checkIfUserExists(userId);
    if (isExistingUser)
    {
        /* Generez request token-ul */
        requestToken = generate_access_token((char*)userId.c_str());
        cout<<"  RequestToken = "<<requestToken<<endl;
        usersAndReqTokens.at(userId) = requestToken;
    }
    else if (!isExistingUser)
    {
        requestToken = "USER_NOT_FOUND";
    }

    /* Setez raspunsul */
    response->token_resp = (char*)requestToken.c_str();
    fflush(stdout);
    return response;
}

req_acc_token_resp *request_access_token_1_svc(req_acc_token_param *data, struct svc_req *cl)
{
    static string userId;
    static string requestToken;
    static string accessToken;
    static string refreshToken;
    static bool isRefreshNeeded = false;
    static req_acc_token_resp *response = (req_acc_token_resp*)malloc(sizeof(req_acc_token_resp));

    /* Preiau id-ul userului si token-ul de request trimis ca si parametru */
    userId = data->id_clnt;
    requestToken = data->token;

    /* Verific daca token-ul este semnat(adica daca are permisiuni atasate) */
    if (reqTokensAndPermisions.at(requestToken) == "*,-")
    {
        accessToken = "REQUEST_DENIED";
    }
    else
    {
        /* Generez acces token-ul */
        accessToken = generate_access_token((char*)requestToken.c_str());
        cout<<"  AccessToken = "<<accessToken<<endl;

        /* Verific daca am nevoie de token de refresh */
        if(userId.size() == 16)
        {
            isRefreshNeeded = true;
            userId = userId.substr(0, 15);
        }

        /* Adaug acces token-ul in map */
        if (checkIfUserExists(userId))
        {
            usersAndAcceptTokens.at(userId) = accessToken;
            refreshToken = tokenTemp;
            accTokensAndRefTokens.insert(pair<string, string>(accessToken, refreshToken));

            if (isRefreshNeeded)
            {
                /* Generez refresh token-ul */
                refreshToken = generate_access_token((char*)accessToken.c_str());
                accTokensAndRefTokens.at(accessToken) = refreshToken;
                cout<<"  RefreshToken = "<<refreshToken<<endl;
            }
            else
            {
                refreshToken = tokenTemp;
            }
        }
    }

    /* Setez raspunsul */
    response->token_rers = (char*)accessToken.c_str();
    response->token_regen = (char*)refreshToken.c_str();
    response->per_valab = valability;

    accTokensAndValability.insert(pair<string, int>(accessToken, valability));
    fflush(stdout);
    return response;
};

val_del_act_resp *validate_delegated_action_1_svc(val_del_act_param *data, struct svc_req *cl)
{
    static string tipOperatie;
    static string resursa;
    static string mesaj;
    static string accTokenForResources;
    static val_del_act_resp *response = (val_del_act_resp*)malloc(sizeof(val_del_act_resp));

    /* Preiau tipul operatiei, resursa si token-ul de acces trimis ca si parametru */
    tipOperatie = data->tip_op;
    resursa = data->resursa;
    accTokenForResources = data->token_rers;

    /* Verific daca token-ul este valid */
    if (accTokenForResources != tokenTemp)
    {
        /* Determin user-ul asociat token-ului de access */
        const string userId = getUserWithAccesToken(accTokenForResources);
        string requestToken = usersAndReqTokens.at(userId);
        const bool isReceivedTokenOk = (accTokenForResources == usersAndAcceptTokens.at(userId));
        string currApprovals = "*,-";

        /* Verific daca am approvals disponibile */
        if (reqTokensAndPermisions.size() != 0)
        {
            if (reqTokensAndPermisions.find(requestToken) != reqTokensAndPermisions.end())
            {
                currApprovals = reqTokensAndPermisions.at(requestToken);
            }
        }

        /* Verific daca token-ul este asociat cu utilizatorul curent */
        if(!isReceivedTokenOk || (currApprovals == "*,-"))
        {
            cout<<"DENY ("<<tipOperatie<<","<<resursa<<","<<accTokenForResources<<","<<accTokensAndValability.at(accTokenForResources)<<")"<<endl;
            mesaj = "PERMISSION_DENIED";
            response->new_acc_token = (char*)accTokenForResources.c_str();
            response->mesaj = (char*)mesaj.c_str();;

            fflush(stdout);
            return response;
        }

        /* Verific daca token-ul este expirat */
        if (isAccTokenExpired(accTokenForResources))
        {
            /* Verific daca am disponibil un token de refresh */
            const string refreshToken = accTokensAndRefTokens.at(accTokenForResources);
            if (refreshToken != tokenTemp)
            {
                /* Generez noul token de acces */
                cout<<"BEGIN "<<userId<<" AUTHZ REFRESH"<<endl;
                const string newAccToken = generate_access_token((char*)refreshToken.c_str());
                cout<<"  AccessToken = "<<newAccToken<<endl;
                const string newRefreshToken = generate_access_token((char*)newAccToken.c_str());
                cout<<"  RefreshToken = "<<newRefreshToken<<endl;
                /* Updatez token-ul de acces in toate map-urile necesare */
                accTokenForResources = newAccToken;
                usersAndAcceptTokens.at(userId) = newAccToken;
                accTokensAndRefTokens.erase(accTokenForResources);
                accTokensAndRefTokens.insert(pair<string, string>(newAccToken, newRefreshToken));
                accTokensAndValability.erase(accTokenForResources);
                accTokensAndValability.insert(pair<string, int>(newAccToken, valability));
                accTokenForResources = newAccToken;
            }
            else
            {
                cout<<"DENY ("<<tipOperatie<<","<<resursa<<","<<""<<","<<0<<")"<<endl;
                mesaj = "TOKEN_EXPIRED";
                response->new_acc_token = (char*)accTokenForResources.c_str();
                response->mesaj = (char*)mesaj.c_str();;

                return response;
            }
        }

        accTokensAndValability.at(accTokenForResources) = accTokensAndValability.at(accTokenForResources) - 1;

        /* Verific daca exista resursa */
        if(doesRerourceExist(resursa))
        {
            cout<<"DENY ("<<tipOperatie<<","<<resursa<<","<<accTokenForResources<<","<<accTokensAndValability.at(accTokenForResources)<<")"<<endl;
            mesaj = "RESOURCE_NOT_FOUND";
            response->new_acc_token = (char*)accTokenForResources.c_str();
            response->mesaj = (char*)mesaj.c_str();;

            fflush(stdout);
            return response;
        }

        /* Verific daca am permisiunile cerute pt resursa */
        if (doesPermisionExist(resursa, currApprovals, tipOperatie))
        {
            cout<<"DENY ("<<tipOperatie<<","<<resursa<<","<<accTokenForResources<<","<<accTokensAndValability.at(accTokenForResources)<<")"<<endl;
            mesaj = "OPERATION_NOT_PERMITTED";
            response->new_acc_token = (char*)accTokenForResources.c_str();
            response->mesaj = (char*)mesaj.c_str();;

            fflush(stdout);
            return response;
        }
    }
    else
    {
        cout<<"DENY ("<<tipOperatie<<","<<resursa<<","<<""<<","<<0<<")"<<endl;
        mesaj = "PERMISSION_DENIED";
        response->new_acc_token = (char*)tokenTemp.c_str();
        response->mesaj = (char*)mesaj.c_str();;

        fflush(stdout);
        return response;
    }

    cout<<"PERMIT ("<<tipOperatie<<","<<resursa<<","<<accTokenForResources<<","<<accTokensAndValability.at(accTokenForResources)<<")"<<endl;
    response->new_acc_token = (char*)accTokenForResources.c_str();
    response->mesaj = (char*)"PERMISSION_GRANTED";

    fflush(stdout);
    return response;
};

app_req_resp *approve_request_token_1_svc(app_req_param *data, struct svc_req *cl)
{
    static string requestToken;
    static app_req_resp *response = (app_req_resp*)malloc(sizeof(app_req_resp));

    /* Preiau tokenul trimis ca si parametru */
    requestToken = data->token_rers;

    /* Marchez tokenul ca fiind semnat daca are permisiuni */
    const string currPermisions = permisions.front();
    reqTokensAndPermisions.insert(pair<string, string>(requestToken, currPermisions));
    permisions.pop();

    /* Setez raspunsul */
    response->token_perm = (char*)requestToken.c_str();

    fflush(stdout);
    return response;
};

bool checkIfUserExists(const string userId)
{
    /* Caut user-ul in cei stocati */
    if ((usersAndReqTokens.find(userId)) != (usersAndReqTokens.end())) {
        return true;
    }

    return false;
}

string getUserWithAccesToken(const string accessToken)
{
    /* Caut user-ul cu token-ul de acces corespondent */
    for(auto &iterator : usersAndAcceptTokens) {
        if (iterator.second == accessToken) {
            return iterator.first;
        }
    }
}

bool isAccTokenExpired(const string accessToken)
{
    /* Verific daca token-ul de access are valabilitatea expirata */
    if (accTokensAndValability.find(accessToken) != accTokensAndValability.end())
    {
        if (accTokensAndValability.at(accessToken) < 1)
        {
            return true;
        }
    }

    return false;
}

bool doesRerourceExist(const string resource)
{
    /* Verific daca resursa exista in cele stocate */
    if (find(resources.begin(), resources.end(), resource) == resources.end()) {
        return true;
    }

    return false;
}

bool doesPermisionExist(const string resource, const string availableRers, const string operation)
{
    /* Preiau resursele si permisiunile curente */
    const int indexResource = availableRers.find(resource);
    if (indexResource != -1)
    {
        const int start = indexResource + resource.length() + 1;
        const string availablePermisions = availableRers.substr(start, availableRers.find(",", start) - start);
        if (opTypeAndCode.find(operation) != opTypeAndCode.end())
        {
            const char opCurenta = opTypeAndCode.at(operation);

            /* Verific daca permisiunea exista */
            if ((availablePermisions.find(opCurenta) == string::npos) || (availableRers == "*,-")) {
                return true;
            }
        }
        else
        {
            /* Tipul operatiei este invalid */
            return true;
        }
    }
    else
    {
        /* Resursa nu exista in setul de permisiuni */
        return true;
    }

    return false;
}

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
        usersAndReqTokens.insert(pair<string, string>(userId, tokenTemp));
        usersAndAcceptTokens.insert(pair<string, string>(userId, tokenTemp));
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
        valability = stoi(line);

        tokenAvailabilityFile.close();
    }

    /* Initializez map-ul cu operatiile si codurile asociate */
    opTypeAndCode.insert(pair<string, char>("READ", 'R'));
    opTypeAndCode.insert(pair<string, char>("INSERT", 'I'));
    opTypeAndCode.insert(pair<string, char>("MODIFY", 'M'));
    opTypeAndCode.insert(pair<string, char>("DELETE", 'D'));
    opTypeAndCode.insert(pair<string, char>("EXECUTE", 'X'));

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
