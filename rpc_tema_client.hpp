#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include "rpc_tema.h"

using namespace std;

vector<string> lines;
const string tokenTemp = "---------------";
map<string, string> users_and_messages; /* dictionar pentru useri si tokenii de request asociati*/
map<string, string> usersAndReqTokens; /* dictionar pentru useri si tokenii de request asociati*/
map<string, string> usersAndAccessTokens;  /* dictionar pentru useri si tokenii de access asociati*/