#ifndef _DJ_RULE_H_
#define _DJ_RULE_H_

#include <MESA/Maat_rule.h>
#include <MESA/stream.h>
#include <MESA/field_stat.h>
#include <MESA/magellan_logger.h>
//global maat scanner
extern void*		 					g_dj_feather;
extern void* 							g_dj_stat_handle;

//global doc analyse instance
extern void* 							g_dj_doc_instance;


/*cache and send*/
typedef enum 
{
	COMPLETE=0,
	FRAG=1,
	FRAG_END=2,
}APPD_MSG_TYPE;

typedef void* opt_unit_t;
typedef void* dj_cache_t;

#ifdef __cplusplus
extern "C"
{
#endif

/*for 056jcq jt and audit*/
int32_t dj_magellan_write_log (const struct streaminfo* a_tcp,const int user_id,  const int table_id, magellan_opt_t* opt_array, int opt_num,int t_id);

dj_cache_t 	create_dj_cache(const char* protocol, struct streaminfo* a_stream);
void 		set_dj_cache_send(dj_cache_t handle);
void 		destroy_dj_cache(dj_cache_t  handle);
/*
*if set_dj_cache_send, callback add_dj_cache will send cache data, otherwise only cache not send
*return -1: get mem_limit  ; return 0: OK
*opt will be free by add_dj_cache
*/
int 		add_dj_cache(dj_cache_t handle, APPD_MSG_TYPE status, opt_unit_t opt);

/*
*NULL value means nested option, otherwise is simple option
*opt will be free by dj_cache, if not add_dj_cache, please do not create_opt_unit
*/
opt_unit_t 	create_opt_unit(const char* opt_name, const void* opt_value, int opt_len);
void 		append_opt_nested_value(opt_unit_t ext_opt, opt_unit_t inner_opt);

//return 1 if type match, otherwise return 0;
int 		is_zip_type(int doctype);
int 		is_scan_type(int doctype);

/*
 * dj_thread_safe_ctime: thread safe(no lock) time to string
 * tp:current time
 * buf: [out] to store the time string
 * len:buffer length
 */
char *dj_thread_safe_ctime(const time_t *tp, char *buf, int len);
#ifdef __cplusplus
}
#endif

#endif


