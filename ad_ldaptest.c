/* --------------------------------------------------------------------------- *
 * compile:     gcc -o ad_ldaptest ad_ldaptest.c -lldap -llber                 *
 * --------------------------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define LDAP_DEPRECATED 1

#include <ldap.h>

#define LDAP_URI_HOSTPORT    "ldap://10.23.3.22:389"
#define LDAP_SUFFIX_DN       "dc=acorn,dc=com"

#define UNUSED(x) (void)(x)
#define SFREE(x) {if((x)!=NULL)free(x);}
typedef int boolean;
#define FALSE (0)
#define TRUE  !FALSE

/**
 * set of functions working on an array of LDAPURLDesc pointers (this structure is a breakdown of an LDAP URI into its components
 * in order to simplify reference management, pointers to LDAPURLDesc have a typedef: pLDAPURLDesc
 * this array is composed of pointers to LDAPURLDesc and is terminated by a NULL pointer
 **/
typedef LDAPURLDesc* pLDAPURLDesc;
/*
 * add one element to a dynamically allocated array of LDAPURLDesc
 * the added element takes its information from ldapUri, (url typically prone to be parsed with ldap_url_parse)
 * pppLdapUrlDescArray: address of reference to array
 *  reference to this array should be NULL when array is new or previously freed
 */
int addItemToLdapUrlDescArray(const char* ldapUri, pLDAPURLDesc** ppLdapUrlDescArray);
/*
 * free dynamic memory allocated for an array of tReferralDetails as well as the array itself
 *  and set its reference pointer to NULL
 * ppRefDetailTable: reference to array address
 * return number of freed elements in array if okay or a negative number in case of problem
 */
int freeLdapUrlDescArray(pLDAPURLDesc** ppLdapUrlDescArray);
/*
 * returns zero-based index of closest DN in an array of LDAPURLDesc
 * this is done by matching the longest dn found in the array against the dn given as parameter
 * return negative invalid index if not found or error
 */
int lookForClosestDnInLdapUrlDescArray(const char* dn, pLDAPURLDesc* array);
/* test function: should return 0 (errors) */
int __test__LdapUrlDescArray();


/*** tester parameters ***/
 /* TRUE if we want anonymous binding to server */
boolean bAnon=FALSE;
 /* manager password for simple server Authentication*/
char *root_pw           = "secret";
 /* set as non NULL to authenticate user through LDAP... */
const char* userToAuthenticateUid="javier.perez";
 /* with the following password in clear */
const char* userPassword="javier";
/* LDAP server hostname (or IP address) and port number */
char *uri_hostport      = LDAP_URI_HOSTPORT;
 /* root/top/base/suffix distinguished name */
char *suffix_dn         = LDAP_SUFFIX_DN;
 /* manager distinguished name (for simple authentication for binding to server */
char *root_dn           = "cn=Manager,"LDAP_SUFFIX_DN;
/*** end of tester parameters ***/


/* used to store password as an octet string for root */
struct berval simpleSASLCredentials;

/* stores the last LDAP server URI in case of referrals crossed (and captured by rebindCallback) */
char* referralUri_hostport=NULL;

/*
 * trick for simple SASL LDAP server authentication
 *  . tests bAnon (do we want anonymous bind?) and sets simpleSASLCredentials
 *  . return NULL if anonymous, otherwise return 'root_dn'
 *  . good to know: return value is a suitable 'dn' parameter for ldap_sasl_bind_s
 *
 */
const char* setSimpleSASLCredAndReturnDn()
{
	if(bAnon) {
	 simpleSASLCredentials.bv_val=NULL;
	 simpleSASLCredentials.bv_len=0;
	 return(NULL);
	} else {
	 simpleSASLCredentials.bv_val=(char*)root_pw;
	 simpleSASLCredentials.bv_len=strlen(simpleSASLCredentials.bv_val);
	 return(root_dn);
	}
}

pLDAPURLDesc* LdapUrlDescArray=NULL;

int rebindCallback(LDAP* ld, const char* url, ber_tag_t request, ber_int_t msgid, void* params)
{
	int result;

	UNUSED(params);
	result = ldap_sasl_bind_s(ld, setSimpleSASLCredAndReturnDn(), LDAP_SASL_SIMPLE, &simpleSASLCredentials, NULL, NULL, NULL);
	printf("Call to rebindCallback: request: %i, msgid: %i, uri: %s\n", (int)request, (int)msgid, url);
	addItemToLdapUrlDescArray(url, &LdapUrlDescArray);
	return(result);
}

int main(int argc, char **argv) {

  int  result;
  int  ldap_version       = LDAP_VERSION3;
  int* ldap_optReferrals  = LDAP_OPT_ON;
  int  ldap_optDeref      = LDAP_DEREF_ALWAYS;

  LDAP* ldap;
  LDAP* ldapForUserAuth;
  LDAPMessage* answer, * entry;
  BerElement* ber;

  const char* userIdAttrName="uid";

  // The search scope must be either LDAP_SCOPE_SUBTREE or LDAP_SCOPE_ONELEVEL
  int  scope        = LDAP_SCOPE_SUBTREE;
  // The search filter, "(objectClass=*)" returns everything. 
  char filter[255]  = "(uid=*)";
  // The attribute list to be returned, use {NULL} for getting all attributes
  const char* attrs[16] = {NULL};
  // Specify if only attribute types (1) or both type and value (0) are returned
  int  attrsonly      = 0;
  // entries_found holds the number of objects found for the LDAP search
  int  entries_found  = 0;
  // dn holds the DN name string of the object(s) returned by the search
  char *dn            = "";
  // attribute holds the name of the object(s) attributes returned
  char *attribute     = "";
  // values is  array to hold the attribute values of the object(s) attributes
  struct berval **values;
  // credential (password) for bind
  struct berval cred;
  // loop index
  int  i              = 0;

  UNUSED(argc);
  UNUSED(argv);

  printf("__test__LdapUrlDescArray returned %d error(s)\n", __test__LdapUrlDescArray());
  if(userToAuthenticateUid!=NULL) {
	/* in case of user bind authentication, we are just interested in uid of user */
    sprintf(filter, "(%s=%s)", userIdAttrName, userToAuthenticateUid);
    /* and let's restrict interesting attributes to only one */
    attrs[0]=userIdAttrName;
    attrs[1]=NULL;
    printf("Will try to authenticate user %s through LDAP\n", userToAuthenticateUid);
  }

  /* First, we print out an informational message */
  printf("Connecting to host \"%s\"...\n", uri_hostport);

  /* STEP 1: Get a LDAP connection handle and set any session preferences. */
   if (ldap_initialize(&ldap, uri_hostport)!=LDAP_SUCCESS) {
    perror("ldap_init failed");
    exit(EXIT_FAILURE);
  } else {
    printf("Generated LDAP handle\n");
  }

  /* The LDAP_OPT_PROTOCOL_VERSION sessionldap_perror preference specifies the client */
  /* is an LDAPv3 client. */
  result = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

  if (result != LDAP_OPT_SUCCESS) {
	  fprintf(stderr, "ldap_set_option: %s", ldap_err2string(result));
      exit(EXIT_FAILURE);
  } else {
    printf("Set LDAPv3 client version\n");
  }
  if (ldap_set_option(ldap, LDAP_OPT_REFERRALS, ldap_optReferrals) != LDAP_OPT_SUCCESS) {
	  fprintf(stderr, "ldap_set_option LDAP_OPT_REFERRALS: %s", ldap_err2string(result));
  } else {
    printf("Set LDAP opt referrals %s\n", ldap_optReferrals==LDAP_OPT_ON?"ON":"OFF");
  }
  if (ldap_set_option(ldap, LDAP_OPT_DEREF, &ldap_optDeref) != LDAP_OPT_SUCCESS) {
	  fprintf(stderr, "ldap_set_option LDAP_OPT_DEREF: %s", ldap_err2string(result));
  }

  /* allows us to know what's going on with referrals and control credentials on bind  */
  ldap_set_rebind_proc(ldap, rebindCallback, NULL);
  /* STEP 2: Bind to the server */
  // If no DN or credentials are specified, we bind anonymously to the server */
   result = ldap_sasl_bind_s(ldap, setSimpleSASLCredAndReturnDn(), LDAP_SASL_SIMPLE, &simpleSASLCredentials, NULL, NULL, NULL);

  if (result != LDAP_SUCCESS) {
    fprintf(stderr, "ldap_sasl_bind_s: %s\n", ldap_err2string(result));
    exit(EXIT_FAILURE);
  } else {
    printf("LDAP connection successful\n");
  }

  /* STEP 3: Do the LDAP search. */
  result = ldap_search_ext_s(ldap, suffix_dn, scope, filter,
                         (char**)attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer);
  if (result != LDAP_SUCCESS) {
    fprintf(stderr, "ldap_search_s: %s\n", ldap_err2string(result));
    exit(EXIT_FAILURE);
  } else {
    printf("LDAP search successful\n");
  }


  /* Return the number of objects found during the search */
  entries_found = ldap_count_entries(ldap, answer);
  if (entries_found == 0) {
    fprintf(stderr, "LDAP search did not return any data\n");
    dn = ldap_get_dn(ldap, answer);
    if(ldap_is_ldap_url(dn)) {
      printf("Stopped at referral: %s\n", dn);
     }
    exit(EXIT_FAILURE);
  } else {
    printf("LDAP search returned %d objects\n", entries_found);
  }

  /* cycle through all objects returned with our search */
  for (entry = ldap_first_entry(ldap, answer);
       entry != NULL;
       entry = ldap_next_entry(ldap, entry)) {

    /* Print the DN string of the object */
    dn = ldap_get_dn(ldap, entry);
    printf("Found Object Entry: %s\n", dn);

    if(userToAuthenticateUid!=NULL) {
   	  char* referralUri_hostport;
   	  int referralindex;
   	  LDAPURLDesc* pUrlDesc;
   	  if((referralindex=lookForClosestDnInLdapUrlDescArray(dn, LdapUrlDescArray))<0) {
       referralUri_hostport=uri_hostport;
   	  } else {
   		pUrlDesc=LdapUrlDescArray[referralindex];
   		referralUri_hostport=malloc(strlen(pUrlDesc->lud_scheme)+strlen(pUrlDesc->lud_host)+16);
   	    sprintf(referralUri_hostport, "%s://%s:%i", pUrlDesc->lud_scheme, pUrlDesc->lud_host, pUrlDesc->lud_port);
   	  }
      if (ldap_initialize(&ldapForUserAuth, referralUri_hostport)!=LDAP_SUCCESS) {
       perror("ldap_init failed");
       goto auth_end;
     }
      if (ldap_set_option(ldapForUserAuth, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    	  fprintf(stderr, "ldap_set_option LDAP_OPT_PROTOCOL_VERSION: %s", ldap_err2string(result));
       goto auth_end;
     }
     cred.bv_val=(char*)userPassword;
     cred.bv_len=strlen(cred.bv_val);
     result = ldap_sasl_bind_s(ldapForUserAuth, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
     if (result != LDAP_SUCCESS) {
       fprintf(stderr, "User %s (dn: %s) authentication through bind failure: %s\n",
    		   userToAuthenticateUid, dn, ldap_err2string(result));
     } else {
       printf("User %s (dn: %s) authentication through bind successful\n", userToAuthenticateUid, dn);
       ldap_unbind_ext_s(ldapForUserAuth, NULL, NULL);
     }
    auth_end:
	 ldap_memfree(dn);
     break;
    }

    // cycle through all returned attributes
    for (attribute = ldap_first_attribute(ldap, entry, &ber);
         attribute != NULL;
         attribute = ldap_next_attribute(ldap, entry, ber)) {

      /* Print the attribute name */
      printf(" Attribute: %s=", attribute);
      if ((values = ldap_get_values_len(ldap, entry, attribute)) != NULL) {

        /* cycle through all values returned for this attribute */
        for (i = 0; values[i] != NULL; i++) {
          /* print each value of a attribute here */
          printf("%s%s", values[i]->bv_val, values[i+1]==NULL?"\n":",");
        }
        ldap_value_free_len(values);
      }
    }
    ldap_memfree(dn);
  }

  ldap_msgfree(answer);
  ldap_unbind_ext_s(ldap, NULL, NULL);
  SFREE(referralUri_hostport);
  freeLdapUrlDescArray(&LdapUrlDescArray);
  return(EXIT_SUCCESS);
}

int addItemToLdapUrlDescArray(const char* ldapUri, pLDAPURLDesc** ppLdapUrlDescArray)
{
 pLDAPURLDesc* pLdapUrlDescArray;
 LDAPURLDesc* pUrlDesc;
 size_t size;
 if(ppLdapUrlDescArray==NULL)
  return(-1);
 if(ldap_url_parse(ldapUri, &pUrlDesc)!=0)
  return(-2);
 pLdapUrlDescArray=*ppLdapUrlDescArray;
 if(pLdapUrlDescArray==NULL) {
  pLdapUrlDescArray=calloc(sizeof(pLDAPURLDesc), 1);
  if(pLdapUrlDescArray==NULL)
   return(-3);
  *ppLdapUrlDescArray=pLdapUrlDescArray;
 }
 for(size=0; pLdapUrlDescArray[size]!=NULL; size++)
  {}
 size+=2;
 pLdapUrlDescArray=realloc(pLdapUrlDescArray, size*sizeof(pLDAPURLDesc));
 if(pLdapUrlDescArray==NULL)
  return(-4);
 *ppLdapUrlDescArray=pLdapUrlDescArray;
 pLdapUrlDescArray[size-2]=pUrlDesc;
 pLdapUrlDescArray[size-1]=NULL;
 return(0);
}

int freeLdapUrlDescArray(pLDAPURLDesc** ppLdapUrlDescArray)
{
 pLDAPURLDesc* pLdapUrlDescArray;
 size_t size;
 if(ppLdapUrlDescArray==NULL)
  return(-1);
 pLdapUrlDescArray=*ppLdapUrlDescArray;
 for(size=0; pLdapUrlDescArray[size]!=NULL; size++) {
  ldap_free_urldesc(pLdapUrlDescArray[size]);
 }
 free(pLdapUrlDescArray);
 *ppLdapUrlDescArray=NULL;
 return((int)size);
}

int lookForClosestDnInLdapUrlDescArray(const char* dn, pLDAPURLDesc* array)
{
 size_t i;
 int best;
 size_t score, scoreOfBest=0;
 const char* pStr;
 if(array==NULL || dn==NULL)
  return(-10);
 for(i=0, best=-1; array[i]!=NULL; i++)
 {
  score=strlen(array[i]->lud_dn);
  if((pStr=strstr(dn, array[i]->lud_dn))!=NULL && strlen(pStr)==score && score>scoreOfBest) {
   best=(int)i;
  }
 }
 return(best);
}

/*
 * test function on pLDAPURLDesc array with NULL terminated array of strings of format:
 *   ldap://hostport/dn[?attrs[?scope[?filter[?exts]]]]
 * */
const char* _ldapTestUris[] = {
		"ldap://1.2.3.4/ou=finance,dc=acorn,dc=com??sub",
		"ldap://1.2.3.5/ou=lab,dc=acorn,dc=com?uid?sub?(uid=*)",
		"ldap://1.2.3.6/ou=software,ou=lab,dc=acorn,dc=com?uid?base?(uid=*)",
		"ldap://1.2.3.7/ou=electronics,ou=lab,dc=acorn,dc=com?uid?one?(uid=*)",
		NULL
};

const char* _ldapDnToTest[] = {
		"0 uid=smith,ou=accounting,ou=finance,dc=acorn,dc=com",
		"1 gn=mark,sn=wesson,ou=emc,ou=lab,dc=acorn,dc=com",
		"2 uid=luger,ou=tests,ou=software,ou=lab,dc=acorn,dc=com",
		"-1 uid=mauser,ou=tests,ou=software,ou=it,dc=acorn,dc=com",
        "-1 uid=winchester,ou=customs,ou=export,dc=acorn,dc=com",
		NULL
};

int __test__LdapUrlDescArray()
{
 const char *errTag = "__test__LdapUrlDescArray error:";
 const int arrayNetSize=sizeof(_ldapTestUris)/sizeof(*_ldapTestUris)-1;
 pLDAPURLDesc* array=NULL;
 int i;
 int result, expectedResult;
 char str[256];
 int errorQty=0;
 for(i=0; _ldapTestUris[i]!=NULL;i++) {
  result=addItemToLdapUrlDescArray(_ldapTestUris[i], &array);
  if(result!=0) {
   printf("%s failure with error %i on addItemToLdapUrlDescArray with \"%s\"\n", errTag, result, _ldapTestUris[i]);
   errorQty++;
  }
 }
 for(i=0; array[i]!=NULL; i++) {
  if(strstr(_ldapTestUris[i], array[i]->lud_dn)==NULL) {
   printf("%s cannot find dn \"%s\" at index %i", errTag, _ldapTestUris[i], i);
   errorQty++;
  }
 }
 for(i=0; _ldapDnToTest[i]!=NULL; i++) {
  sscanf(_ldapDnToTest[i], "%i %s", &expectedResult, str);
  if(expectedResult!=(result=lookForClosestDnInLdapUrlDescArray(str, array))) {
   printf("%s lookForClosestDnInLdapUrlDescArray for \"%s\" returned %i (expected %i)\n", errTag, str, result, expectedResult);
   errorQty++;
  }
 }
 if((result=freeLdapUrlDescArray(&array))!=arrayNetSize) {
  printf("%s call to freeLdapUrlDescArray brought error %i (should be %i)\n", errTag, result, arrayNetSize);
  errorQty++;
 }
 if(array!=NULL) {
  printf("%s after call to freeLdapUrlDescArray array is not NULL\n", errTag);
  errorQty++;
 }
 return(errorQty);
}
