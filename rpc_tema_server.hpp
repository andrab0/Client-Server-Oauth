#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <queue>

#include "rpc_tema.h"
#include "token.h"

using namespace std;

// static int count = 0;

bool check_if_user_exists(const string user_id);
bool check_if_token_expired(const string acc_token);
bool check_if_resource_exists(const string resource);
bool check_if_permision_exists(const string acc_token, const string permision);
string get_user_for_token(const string acc_token);
const string token_temp = "---------------";

map<string, string> users_and_req_tokens; /* dictionar pentru useri si tokenii de request asociati*/
map<string, string> users_and_acc_tokens; /* dictionar pentru useri si tokenii de accept asociati*/
map<string, string> token_and_refresh; /* dictionar pentru tokenii de accept si tokenii de refresh asociati*/
vector<string> resources; /* vector pentru resurse */
queue<string> permisions; /* coada pentru approvals */
map<string, string> token_and_permisions; /* dictionar pentru tokeni si permisiunile asociate*/
// map<string, bool> token_and_status; /* dictionar pentru tokeni si statusul asociat*/
map<string, int> token_and_counter; /* dictionar pentru tokeni si perioada de valabilitate asociata*/
int valid_time = 0; /* timpul de validitate al token-ului */