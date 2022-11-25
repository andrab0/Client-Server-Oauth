/*
 * Pentru Request authorization ma astept sa primesc id-ul clientului
 * si sa intorc ca raspuns token-ul de acces sau o eroare daca nu exista
 */
struct req_auth_param {
    string id_clnt<>; /* id client */
};

struct req_auth_resp {
    string token_resp<>; /* token de acces sau eroare */
};

/*
 * Pentru Request Access token ma astept sa primesc id-ul si token-ul de acces
 * ale clientului si sa intorc ca raspuns token-ul de acces la resurse, token de
 * refresh, perioada de valabilitate tokeni si o eroare daca token-ul nu este valid
 */
struct req_acc_token_param {
    string id_clnt<>; /* id client */
    string token<>; /* token de acces */
};

struct req_acc_token_resp {
    string token_rers<>; /* token de acces la resurse */
    string token_regen<>; /* token de regenerare acces */
    int per_valab; /* perioada de valabilitate tokens*/
};

/*
 * Pentru Validate Delegated Action ma astept sa primesc tipul operatiei, resursa accesata
 * si token-ul de acces la resursa. Imi intoarce un mesaj legat de validitatea token-ului
 * si eventual un nou token de acces daca am facut refresh
 */
struct val_del_act_param {
    string tip_op<>; /* tipul operatiei */
    string resursa<>; /* resursa accesata */
    string token_rers<>; /* token de acces la resurse */
};

struct val_del_act_resp {
    string new_acc_token<>; /* token nou de acces daca se genereaza */
    string mesaj<>; /* mesaj legat de validitatea token-ului */
};

/*
 * Pentru Approve Request Token ma astept sa primesc token-ul de acces la resurse si sa
 * imi intoarca un token-ul cu permisiunile atasate sau nu
 */
struct app_req_param {
    string token_rers<>; /* token de acces la resurse */
};

struct app_req_resp {
    string token_perm<>; /* token cu permisiunile atasate sau nu */
};

program RPC_TEMA_PROG {
    version RPC_TEMA_VERS {
        req_auth_resp Request_Authorization(req_auth_param) = 1;
        req_acc_token_resp Request_Access_Token(req_acc_token_param) = 2;
        val_del_act_resp Validate_Delegated_Action(val_del_act_param) = 3;
        app_req_resp Approve_Request_Token(app_req_param) = 4;
    } = 1;
} = 135792468; /* numar dubios ca sa fiu sigura ca e unic */