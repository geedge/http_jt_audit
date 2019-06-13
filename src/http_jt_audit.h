#ifndef __JT_ADUIT_HTTP_PLUG_H__
#define  __JT_ADUIT_HTTP_PLUG_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define	REGISTER_TABLE_NUM				1
#define	REGISTER_TABLE_URL_PZ	0


#define	MAX_RESULT_NUM			16
#define	MAX_FILEPATH_LEN		128


#define	SEND_LOG_MAGELLAN_OPT_NUM	32

#define  IP_REQ_NAME      "JT_IP_PKT"

typedef  struct target_tag_t
{
    int type;		/*业务类型 */
    int rule_id;	/*规则ID */
    short risk;		/* 告警级别 */
   	char id[22];		/* 唯一日志ID */
	void *dns_ip;	/*	仅DNS使用 */
}target_tag;

typedef struct _opt_common
{
	int len;
	char type;
	char *value;
}opt_common_t;

typedef struct _process_context
{
	int do_blacklist;
	int hit_config_num;
	int m_opt_index;
	int method_check;
	int res_code_check;
	int user_agent_check;
	int cookie_check;
	int server_check;
	int refer_check;
	int url_check;
	int domain_check;
	magellan_opt_t m_opt[SEND_LOG_MAGELLAN_OPT_NUM];
}process_context_t;

typedef struct _jt_aduit_http_info
{
	int label_id;
	int log_level;
	int audit_level;
	int table_id[REGISTER_TABLE_NUM];
	char absolute_path[MAX_FILEPATH_LEN];
	char config_filepath[MAX_FILEPATH_LEN];
	char runlog_path[MAX_FILEPATH_LEN];
	void *runlog;
}g_jt_aduit_http_info_t;


unsigned char JT_AUDIT_HTTP_PLUG_ENTRY(stSessionInfo* session_info, void **param, int thread_seq, struct streaminfo *a_tcp, void *a_packet);
int JT_AUDIT_HTTP_PLUG_INIT(void);
void JT_AUDIT_HTTP_PLUG_DESTROY(void);

#ifdef __cplusplus
}
#endif

#endif


