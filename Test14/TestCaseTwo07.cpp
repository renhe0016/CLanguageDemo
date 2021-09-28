#ifdef PROXYSQLCLICKHOUSE
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

ClickHouse_Authentication::ClickHouse_Authentication() {
int ClickHouse_Authentication::increase_frontend_user_connections(char *username, int *mc) {
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;
	ch_creds_group_t &cg=creds_frontends;
	int ret=0;
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, ch_account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		ch_account_details_t *ad=it->second;
		if (ad->max_connections > ad->num_connections_used) {
			ret=ad->max_connections-ad->num_connections_used;
			ad->num_connections_used++;
		}
		if (mc) {
			*mc=ad->max_connections;
		}
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
	return ret;
}

void ClickHouse_Authentication::decrease_frontend_user_connections(char *username) {
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;
	ch_creds_group_t &cg=creds_frontends;
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, ch_account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		ch_account_details_t *ad=it->second;
		if (ad->num_connections_used > 0) {
			ad->num_connections_used--;
		}
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
}

bool ClickHouse_Authentication::del(char * username, enum cred_username_type usertype, bool set_lock) {
	bool ret=false;
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;

	ch_creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

	if (set_lock)
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
		pthread_rwlock_wrlock(&cg.lock);
#else
		spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, ch_account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		ch_account_details_t *ad=lookup->second;
		cg.cred_array->remove_fast(ad);
		cg.bt_map.erase(lookup);
		free(ad->username);
		free(ad->password);
		if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
		free(ad->default_schema);
		free(ad);
		ret=true;
	}
	if (set_lock)
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
		pthread_rwlock_unlock(&cg.lock);
#else
		spin_wrunlock(&cg.lock);
#endif
	return ret;
};

bool ClickHouse_Authentication::set_SHA1(char * username, enum cred_username_type usertype, void *sha_pass) {
	bool ret=false;
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;

	ch_creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, ch_account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		ch_account_details_t *ad=lookup->second;
		if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
		if (sha_pass) {
			ad->sha1_pass=malloc(SHA_DIGEST_LENGTH);
			memcpy(ad->sha1_pass,sha_pass,SHA_DIGEST_LENGTH);
		}
		ret=true;
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
   spin_wrunlock(&cg.lock);
#endif
	return ret;
};

bool ClickHouse_Authentication::exists(char * username) {
	bool ret = false;
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	ch_creds_group_t &cg = creds_frontends ;
	pthread_rwlock_rdlock(&cg.lock);
	std::map<uint64_t, ch_account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		ret = true;
	}
	pthread_rwlock_unlock(&cg.lock);
	return ret;
}

