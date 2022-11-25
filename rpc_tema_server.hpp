#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <algorithm>

#include "rpc_tema_svc.h"
#include "rpc_tema.h"
#include "token.h"

using namespace std;

bool checkIfUserExists(const string userId);
bool isAccTokenExpired(const string accessToken);
bool doesRerourceExist(const string resource);
bool doesPermisionExist(const string resource, const string availableRers, const string operation);
string getUserWithAccesToken(const string accessToken);
const string tokenTemp = "---------------";
map<string, string> usersAndReqTokens; /* dictionar pentru useri si tokenii de request asociati*/
map<string, string> usersAndAcceptTokens; /* dictionar pentru useri si tokenii de access asociati*/
map<string, string> accTokensAndRefTokens; /* dictionar pentru tokenii de access si tokenii de refresh asociati*/
vector<string> resources; /* vector pentru resurse */
queue<string> permisions; /* coada pentru approvals */
map<string, char> opTypeAndCode; /* dictionar pentru operatii si codurile asociate */
map<string, string> reqTokensAndPermisions; /* dictionar pentru tokeni si permisiunile asociate*/
map<string, int> accTokensAndValability; /* dictionar pentru tokeni si perioada de valabilitate asociata*/
int valability = 0; /* timpul de validitate al token-ului */