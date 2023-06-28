// #ifdef ACL_SUPP
#include "include/acl_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"
#include <sqlite3.h>

typedef struct user {
	char *username;
	char *password;
} user;

static bool
match_rule_content_str(acl_rule_ct *ct, const char *cmp_str)
{
	bool match = false;
	if (ct->type == ACL_RULE_ALL) {
		match = true;
	} else if (ct->type == ACL_RULE_SINGLE_STRING && cmp_str != NULL &&
	    strcmp(ct->value.str, cmp_str) == 0) {
		match = true;
	}
	return match;
}

char *
custom_cat(char *s1, char *s2)
{
	if (s1 == NULL && s2 == NULL)
		return NULL;
	if (s1 == NULL)
		return strdup(s2);
	if (s2 == NULL)
		return strdup(s1);
	char *result = calloc(strlen(s1) + strlen(s2) + 1, sizeof(char));
	strcpy(result, s1);
	strcat(result, s2);
	return result;
}

int
callback(void *NotUsed, int argc, char **argv, char **azColName)
{

	user *tmp = (user *) NotUsed;

	// printf("here ===> %s: ", (const char *) NotUsed);

	for (int i = 0; i < argc; i++) {

		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
		if (strcmp(azColName[i], "username") == 0) {
			tmp->username = strdup(argv[i]);
		} else if (strcmp(azColName[i], "password") == 0) {
			tmp->password = strdup(argv[i]);
		}
	}

	// printf("\n");

	return 0;
}

bool
auth_acl(conf *config, acl_action_type act_type, conn_param *param,
    const char *topic)
{
	sqlite3 *db;
	char    *err_msg = 0;
	user    *u       = calloc(1, sizeof(user));

	int rc = sqlite3_open("/srv/db/edge.sqlite", &db);

	if (rc != SQLITE_OK) {

		fprintf(
		    stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);

		return false;
	}

	char *sql = custom_cat("SELECT * FROM credentials WHERE username = '",
	    (const char *) conn_param_get_username(param));
	sql       = custom_cat(sql, "'");
	rc        = sqlite3_exec(db, sql, callback, (void *) u, &err_msg);

	printf("username: %s | param: %s\n", u->username,
	    conn_param_get_username(param));
	printf("password: %s | param: %s\n", u->password,
	    conn_param_get_password(param));

	if (rc != SQLITE_OK) {

		fprintf(stderr, "Failed to select data\n");
		fprintf(stderr, "SQL error: %s\n", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);

		return false;
	}

	sqlite3_close(db);
	if (u->username != NULL && u->password != NULL) {
		fprintf(stderr, "s");
		if (strcmp(conn_param_get_username(param), u->username) == 0 &&
		    strcmp(conn_param_get_password(param), u->password) == 0) {
			  fprintf(stderr, "s");
			return true;
		}
		else if(strcmp(conn_param_get_password(param), u->password) != 0 ){
	                fprintf(stderr, "password incorrect ! \n");
	                return false;
	        }
	        else {
	                fprintf(stderr, "username incorrect ! \n");
	                return false;
	        }
	}
	// #endif
}
	
// #endif
