#ifdef PROXYSQLCLICKHOUSE
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

ClickHouse_Authentication::ClickHouse_Authentication() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_init(&creds_backends.lock, NULL);
	pthread_rwlock_init(&creds_frontends.lock, NULL);
#else
	spinlock_rwlock_init(&creds_backends.lock);
	spinlock_rwlock_init(&creds_frontends.lock);
#endif
	creds_backends.cred_array = new PtrArray();
	creds_frontends.cred_array = new PtrArray();
};

ClickHouse_Authentication::~ClickHouse_Authentication() {
	reset();
	delete creds_backends.cred_array;
	delete creds_frontends.cred_array;
};

void ClickHouse_Authentication::print_version() {
		fprintf(stderr,"Standard ProxySQL ClickHouse Authentication rev. %s -- %s -- %s\n", PROXYSQL_CLICKHOUSE_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};

void ClickHouse_Authentication::set_all_inactive(enum cred_username_type usertype) {
	ch_creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	unsigned int i;
	for (i=0; i<cg.cred_array->len; i++) {
		ch_account_details_t *ado=(ch_account_details_t *)cg.cred_array->index(i);
		ado->__active=false;
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
}

void ClickHouse_Authentication::remove_inactives(enum cred_username_type usertype) {
	ch_creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	unsigned int i;
__loop_remove_inactives:
	for (i=0; i<cg.cred_array->len; i++) {
		ch_account_details_t *ado=(ch_account_details_t *)cg.cred_array->index(i);
		if (ado->__active==false) {
			del(ado->username,usertype,false);
			goto __loop_remove_inactives; // we aren't sure how the underlying structure changes, so we jump back to 0
		}
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
}

bool ClickHouse_Authentication::add(char * username, char * password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections) {
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	ch_creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, ch_account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	// few changes will follow, due to issue #802
	ch_account_details_t *ad=NULL;
	bool new_ad=false;
	if (lookup != cg.bt_map.end()) {
		ad=lookup->second;
		if (strcmp(ad->password,password)) {
			free(ad->password);
			ad->password=strdup(password);
			if (ad->sha1_pass) {
				free(ad->sha1_pass);
				ad->sha1_pass=NULL;
			}
		}
		if (strcmp(ad->default_schema,default_schema)) {
			free(ad->default_schema);
			ad->default_schema=strdup(default_schema);
		}
  } else {
		ad=(ch_account_details_t *)malloc(sizeof(ch_account_details_t));
		ad->username=strdup(username);
		ad->default_schema=strdup(default_schema);
		ad->password=strdup(password);
		new_ad=true;
		ad->sha1_pass=NULL;
		ad->num_connections_used=0;
	}

	ad->use_ssl=use_ssl;
	ad->default_hostgroup=default_hostgroup;
	ad->schema_locked=schema_locked;
	ad->transaction_persistent=transaction_persistent;
	ad->__active=true;
	if (new_ad) {
		cg.bt_map.insert(std::make_pair(hash1,ad));
		cg.cred_array->add(ad);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
	return true;
};

int ClickHouse_Authentication::dump_all_users(ch_account_details_t ***ads, bool _complete) {
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&creds_frontends.lock);
	pthread_rwlock_rdlock(&creds_backends.lock);
#else
	spin_rdlock(&creds_frontends.lock);
	spin_rdlock(&creds_backends.lock);
#endif
	int total_size;
	int idx_=0;
	unsigned i=0;
	ch_account_details_t **_ads;
	total_size=creds_frontends.cred_array->len;
	if (_complete) {
		total_size+=creds_backends.cred_array->len;
	}
	if (!total_size) goto __exit_dump_all_users;
	_ads=(ch_account_details_t **)malloc(sizeof(ch_account_details_t *)*total_size);
	for (i=0; i<creds_frontends.cred_array->len; i++) {
		ch_account_details_t *ad=(ch_account_details_t *)malloc(sizeof(ch_account_details_t));

	}	
}
