#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <time.h>

#include <MESA/stream.h>
#include <MESA/http.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/magellan_logger.h>

#include "inc/qdjcq_magellan_id.h"
#include "inc/dj_rule.h"
#include "http_jt_audit.h"

const char HTTP_JT_AUDIT_VERSION_20170721 = 0;

g_jt_aduit_http_info_t g_jt_aduit_http_info;
const char *g_conf_file_path = "./djconf/http_jt_audit.conf";
const char *module_name = "JT_HTTP_PLUG";

const char *register_table_name[REGISTER_TABLE_NUM] = {"URL_PZ"};
unsigned short http_file_sequence = 0;

#ifndef atomic_read
#define atomic_read(x) __sync_add_and_fetch((x),0)
#endif

#ifndef atomic_add 
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#endif

#ifndef atomic_set
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#endif 

void free_project_req(int thread_seq, void *project_req)
{
	if(project_req != NULL)
	{
		dictator_free(thread_seq, project_req);
		project_req = NULL;
	}
	
}

void http_free_magellan_opt(magellan_opt_t *m_opt, int thread_seq)
{
	if(m_opt->opt_value != NULL)
	{
		dictator_free(thread_seq, (void *)m_opt->opt_value);
		m_opt->opt_value = NULL;
	}
}

void http_time_to_string(char *time_str, unsigned int time_str_len)
{
	time_t  t;
	time(&t);
	dj_thread_safe_ctime(&t, time_str, time_str_len);
}

int http_get_magellan_opt(magellan_opt_t *m_opt, int count, char *buf, int buflen, int type, int thread_seq)
{
	if(buf == NULL || buflen == 0)
	{
		return 0;
	}
	
	if(count >= SEND_LOG_MAGELLAN_OPT_NUM)
		return 0;
	
	m_opt->opt_len= buflen;
	m_opt->opt_type= type;
	m_opt->opt_value= (char *)dictator_malloc(thread_seq, m_opt->opt_len);
	memcpy((void *)m_opt->opt_value, (void *)buf, buflen);
	
	return 1;
}

int get_tuple4_opt(magellan_opt_t **opt, struct streaminfo *a_tcp, int thread_seq)
{
	int ret = -1, index = 0;
	char mac_str[32], ip_str[32];
	void *out_value = NULL;
	struct layer_addr_ipv4 *ipv4 = NULL;
	struct layer_addr_mac *mac = NULL;
	
	ret = get_rawpkt_opt_from_streaminfo(a_tcp, RAW_PKT_GET_DATA, out_value);
	if(ret < 0)
	{
		MESA_handle_runtime_log(g_jt_aduit_http_info.runlog, RLOG_LV_FATAL, "GET_TUPLE$_OPT", "No support get MAC ...");
		return -1;
	}

	mac = (struct layer_addr_mac *)out_value;
	//½«¿É±ä¸ö²ÎÊý°´ÕÕformat¸ñÊ½»¯³É×Ö·û´®
	snprintf(mac_str, 32, "%02x-%02x-%02x-%02x-%02x-%02x", mac->dst_mac[0], mac->dst_mac[1],
							mac->dst_mac[2], mac->dst_mac[3], mac->dst_mac[4], mac->dst_mac[5]);
	index+=http_get_magellan_opt(opt[index],index,mac_str,strlen(mac_str), MAGELLAN_OPT_DMAC, thread_seq);

	snprintf(mac_str, 32, "%02x-%02x-%02x-%02x-%02x-%02x", mac->src_mac[0], mac->src_mac[1],
							mac->src_mac[2], mac->src_mac[3], mac->src_mac[4], mac->src_mac[5]);
	index+=http_get_magellan_opt(opt[index],index,mac_str,strlen(mac_str), MAGELLAN_OPT_SMAC, thread_seq);
	
	if(a_tcp->addr.addrtype == ADDR_TYPE_IPV4)
	{
		ipv4 = a_tcp->addr.ipv4;
		inet_ntop(AF_INET, (const void *)&ipv4->daddr, ip_str, sizeof(ip_str));
		index+=http_get_magellan_opt(opt[index],index, ip_str,strlen(ip_str), MAGELLAN_OPT_DIP, thread_seq);
		index+=http_get_magellan_opt(opt[index],index, (char *)&ipv4->dest, sizeof(ipv4->dest), MAGELLAN_OPT_DPORT, thread_seq);
		inet_ntop(AF_INET, (const void *)&ipv4->saddr, ip_str, sizeof(ip_str));
		index+=http_get_magellan_opt(opt[index],index, ip_str,strlen(ip_str), MAGELLAN_OPT_SIP, thread_seq);
		index+=http_get_magellan_opt(opt[index],index, (char *)&ipv4->source, sizeof(ipv4->source), MAGELLAN_OPT_SPORT, thread_seq);
	}

	return index;
}

int http_init_process_context(process_context_t **process_context, int thread_seq)
{
	process_context_t *context = (process_context_t *)dictator_malloc(thread_seq, sizeof(process_context_t));
	memset(context, 0 , sizeof(process_context_t));
	
	*process_context = context;
	
	return 1;
}

void http_destroy_process_context(process_context_t *process_context, int thread_seq)
{
	int i = 0;
	
	if(process_context->m_opt_index != 0)
	{
		for(i = 0; i < process_context->m_opt_index; i++)
		{
			http_free_magellan_opt(&(process_context->m_opt[i]), thread_seq);
		}
	}
	
	dictator_free(thread_seq,process_context);
	process_context = NULL;
}
	
	unsigned char JT_AUDIT_HTTP_PLUG_ENTRY(stSessionInfo* session_info, void **param, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
	{
		int ret = PROT_STATE_GIVEME;
		int found_pos = 0, file_seq = 0, i = 0;
		time_t alarm_time;
		char *method = NULL;
		const char *transf_proto = "TCP";
		const char *app_proto = "http";
		scan_status_t scan_mid = NULL;
		target_tag *tag = NULL;
		struct Maat_rule_t scan_result[MAX_RESULT_NUM];
		struct http_infor_t *http_info = (http_infor *)session_info->app_info;
		process_context_t *context = (process_context_t *)*param;
		char nothing[] = "NULL";
		char *nothing_p = nothing;
		char buffer_url[1024] = {0};
		char domain[1024] = {0};
		int opt_index = 0;
	
		if(*param == NULL)
		{
			if((http_init_process_context(&context, thread_seq)) < 0)
			{
				MESA_handle_runtime_log(g_jt_aduit_http_info.runlog, RLOG_LV_FATAL, module_name, "<%s>%d: init_process_context failed ...", __FILE__, __LINE__);
				return PROT_STATE_DROPME;
			}
			*param = context;
		}

		switch(session_info->prot_flag)
		{
			case HTTP_REQ_LINE:
				method = (char *)http_get_method(http_info->method);
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
									method, strlen(method), MAGELLAN_OPT_METHOD, thread_seq);
				context->method_check = 1;
				break;
			case HTTP_RES_LINE:
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
									(char *)&http_info->res_code, sizeof(http_info->res_code), MAGELLAN_OPT_RET_CODE, thread_seq);
				context->res_code_check = 1;
				break;
			case HTTP_HOST:
				if(session_info->buflen != 0)
					context->domain_check = 1;
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_DOMAIN, thread_seq);
				break;
			case HTTP_MESSAGE_URL:
				if(session_info->buflen != 0)
					context->url_check = 1;

				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
								(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_URL, thread_seq);

				context->hit_config_num = Maat_full_scan_string(g_dj_feather,
													g_jt_aduit_http_info.table_id[REGISTER_TABLE_URL_PZ],
													CHARSET_NONE,
													(const char *)session_info->buf,
													session_info->buflen,
													scan_result,
													&found_pos,
													MAX_RESULT_NUM,
													&scan_mid,
													thread_seq
												);
				Maat_clean_status(&scan_mid);
				/*if(context->hit_config_num <= 0)
				{
					ret = PROT_STATE_DROPME;
					//break;
				}*/
	
				tag = (target_tag *)dictator_malloc(thread_seq, sizeof(target_tag));
				memset(tag, 0, sizeof(target_tag));
				
				for(i = 0; i < context->hit_config_num; i++)
				{
					if((scan_result[i].action == 1))
					{
						if(context->do_blacklist == 0)
						{
							tag->risk = scan_result[i].do_log;
						}
						else
						{
							if(scan_result[i].do_log >= tag->risk)
							{
								tag->risk = scan_result[i].do_log;
							}
						}
						tag->type = scan_result[i].service_id;
						tag->rule_id = scan_result[i].config_id;
						context->do_blacklist = scan_result[i].action;
					}

				}
				//白名单逻辑,直接break并释放tag，退出
				if(context->do_blacklist == 0 && context->hit_config_num > 0)
				{
					if(tag != NULL)
					{
						dictator_free(thread_seq,tag);
						tag = NULL;
					}
					http_destroy_process_context(context, thread_seq);
					*param = NULL;
					ret = PROT_STATE_DROPME;
					return ret; 
				}
			
				
				
				if(context->do_blacklist > 0)
				{
					atomic_add(&http_file_sequence, 1);
					file_seq = atomic_read(&http_file_sequence);
					alarm_time =  time(NULL);
					snprintf(tag->id, sizeof(tag->id), "%u%lu%u", TABID_URL_LISTEN_ALARM, alarm_time, file_seq);
								
					project_req_add_struct(a_tcp, g_jt_aduit_http_info.label_id, (void *)tag);
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
								tag->id, strlen(tag->id), MAGELLAN_OPT_ID, thread_seq);
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
								(char *)&tag->rule_id, sizeof(tag->rule_id), MAGELLAN_OPT_RULE_ID, thread_seq);
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
								(char *)&tag->risk, sizeof(tag->risk), MAGELLAN_OPT_RISK, thread_seq);

					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
								(char *)&alarm_time, sizeof(alarm_time), MAGELLAN_OPT_CAP_TIME, thread_seq);
				}
				/*if(tag !=NULL)
					{
						dictator_free(thread_seq,tag);
						tag = NULL;
					}*/

				break;
			case HTTP_USER_AGENT:			
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_USER_AGENT, thread_seq);
				context->user_agent_check = 1;
				break;
			case HTTP_COOKIE:			
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_COOKIE, thread_seq);
				context->cookie_check = 1;
				break;
			case HTTP_SERVER:
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							//(char *)session_info->buf, strlen((char *)session_info->buf), MAGELLAN_OPT_SERVER, thread_seq);
							(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_SERVER, thread_seq);
				context->server_check = 1;
				break;
			case HTTP_REFERER:
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)session_info->buf, session_info->buflen, MAGELLAN_OPT_REFER, thread_seq);
				context->refer_check = 1;
				break;
			default:
				break;
		}
	
		if((session_info->session_state&SESSION_STATE_CLOSE) || (ret&PROT_STATE_DROPME))
		{
			if(context->hit_config_num > 0 && context->do_blacklist > 0)//ÃüÖÐÇÒÖ»ÒªÓÐºÚÃûµ¥£¬Éó¼ÆÕìÌý¶¼¼ÇÂ¼
			{
				//domain
				
				if(context->method_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_METHOD, thread_seq);

				if(context->res_code_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,(char *)&context->res_code_check, sizeof(int), MAGELLAN_OPT_RET_CODE, thread_seq);

				if(context->user_agent_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_USER_AGENT, thread_seq);

				if(context->cookie_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_COOKIE, thread_seq);

				if(context->server_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_SERVER, thread_seq);

				if(context->refer_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_REFER, thread_seq);

				if(context->domain_check == 0)
				{
					opt_index = context->m_opt_index;
					for(i = 0; i < opt_index; i++)
					{
						if(context->m_opt[i].opt_type == MAGELLAN_OPT_URL)
						{
							int j = 0;
							if(context->m_opt[i].opt_len > 1024)
							{
								memcpy(buffer_url,context->m_opt[i].opt_value,1024);
							}
							else
							{
								memcpy(buffer_url,context->m_opt[i].opt_value,context->m_opt[i].opt_len);
							}
							int len_url = strlen(buffer_url);
							for(j = 0;j<len_url;j++)
							{
								if(buffer_url[j] - 0 == 47)
									break;
								domain[j] = buffer_url[j];
							}
						}
					}
					if(strlen(domain) == 0)
						context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_DOMAIN, thread_seq);
					else
						context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,domain, strlen(domain), MAGELLAN_OPT_DOMAIN, thread_seq);

				}

				char cur_time_str[20] = {0};
				http_time_to_string(cur_time_str, sizeof(cur_time_str));
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							cur_time_str,strlen(cur_time_str),MAGELLAN_OPT_TIME,thread_seq);
				time_t  captime = time(NULL);
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)&captime,sizeof(time_t),MAGELLAN_OPT_CAP_TIME,thread_seq);
				dj_magellan_write_log(a_tcp, QDJCQ_MGLL_USERID, TABID_URL_LISTEN_ALARM, context->m_opt, context->m_opt_index, thread_seq);
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)transf_proto, strlen(transf_proto)+1, MAGELLAN_OPT_PROTOCOL, thread_seq);
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)app_proto, strlen(app_proto)+1, MAGELLAN_OPT_APP, thread_seq);
				dj_magellan_write_log(a_tcp, QDJCQ_MGLL_USERID, TABID_WEB_AUDIT_LOG, context->m_opt, context->m_opt_index, thread_seq);

			}
			else if(context->hit_config_num > 0 && context->do_blacklist == 0)//Èç¹ûÈ«°×£¬NULL
			{
				MESA_handle_runtime_log(g_jt_aduit_http_info.runlog, RLOG_LV_FATAL, "http_jt_audit", "filter ...");
			}
			else//Èç¹ûÃ»ÓÐÃüÖÐ£¬Ö»Êä³öÉó¼ÆÈÕÖ¾
			{
				char cur_time_str[20] = {0};
				http_time_to_string(cur_time_str, sizeof(cur_time_str));
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							cur_time_str,strlen(cur_time_str),MAGELLAN_OPT_TIME,thread_seq);
				
				if(context->url_check == 0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_URL, thread_seq);

				if(context->method_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_METHOD, thread_seq);

				if(context->res_code_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,(char *)&context->res_code_check, sizeof(int), MAGELLAN_OPT_RET_CODE, thread_seq);

				if(context->user_agent_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_USER_AGENT, thread_seq);

				if(context->cookie_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_COOKIE, thread_seq);

				if(context->server_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_SERVER, thread_seq);

				if(context->refer_check==0)
					context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,nothing_p, strlen(nothing_p), MAGELLAN_OPT_REFER, thread_seq);

				if(context->domain_check == 0)
				{
					opt_index = context->m_opt_index;
					for(i = 0; i < opt_index; i++)
					{
						if(context->m_opt[i].opt_type == MAGELLAN_OPT_URL)
						{
							int j;
							if(context->m_opt[i].opt_len > 1024)
							{
								memcpy(buffer_url,context->m_opt[i].opt_value,1024);
							}
							else
							{
								memcpy(buffer_url,context->m_opt[i].opt_value,context->m_opt[i].opt_len);
							}
							int len_url = strlen(buffer_url);
							for(j = 0;j<len_url;j++)
							{
								if(buffer_url[j] - 0 == 47)
									break;
								domain[j] = buffer_url[j];
							}
						}
					}
					if(strlen(domain) == 0)
						context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index, nothing_p, strlen(nothing_p), MAGELLAN_OPT_DOMAIN, thread_seq);
					else
						context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,domain, strlen(domain), MAGELLAN_OPT_DOMAIN, thread_seq);

				}

				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)transf_proto, strlen(transf_proto)+1, MAGELLAN_OPT_PROTOCOL, thread_seq);
				context->m_opt_index+=http_get_magellan_opt(&context->m_opt[context->m_opt_index],context->m_opt_index,
							(char *)app_proto, strlen(app_proto)+1, MAGELLAN_OPT_APP, thread_seq);

				if(g_jt_aduit_http_info.audit_level == 0)
					dj_magellan_write_log(a_tcp, QDJCQ_MGLL_USERID, TABID_WEB_AUDIT_LOG, context->m_opt, context->m_opt_index, thread_seq);
			}
			http_destroy_process_context(context, thread_seq);
			*param = NULL;
			return PROT_STATE_DROPME;
		}
	
		return ret;
	}
	


	
int JT_AUDIT_HTTP_PLUG_INIT(void)
{
	int i = 0, ret = 0;
	
	MESA_load_profile_int_def(g_conf_file_path, "Moudle", "AUDIT_LEVEL", &g_jt_aduit_http_info.audit_level, 0);
	MESA_load_profile_int_def(g_conf_file_path, "Moudle", "LOG_LEVEL", &g_jt_aduit_http_info.log_level, 30);
	MESA_load_profile_string_def(g_conf_file_path, "Moudle", "LOG_PATH", g_jt_aduit_http_info.runlog_path, MAX_FILEPATH_LEN,NULL);

	g_jt_aduit_http_info.runlog = MESA_create_runtime_log_handle(g_jt_aduit_http_info.runlog_path, g_jt_aduit_http_info.log_level);
	if(g_jt_aduit_http_info.runlog == NULL)
	{
		printf("MESA_create_handle failed ... \n\n");
		return -1;
	}
	
	for(i = 0; i < REGISTER_TABLE_NUM; i++)
	{
		g_jt_aduit_http_info.table_id[i] = Maat_table_register(g_dj_feather, register_table_name[i]);

		if(g_jt_aduit_http_info.table_id[i] < 0)
		{
			MESA_handle_runtime_log(g_jt_aduit_http_info.runlog, RLOG_LV_FATAL, "JT_AUDIT_HTTP_PLUG_INIT", "Register table id failed ...");
			return -1;
		}
	}
	

	g_jt_aduit_http_info.label_id = project_producer_register(IP_REQ_NAME, PROJECT_VAL_TYPE_STRUCT, free_project_req);
	if(ret < 0)
	{
		MESA_handle_runtime_log(g_jt_aduit_http_info.runlog, RLOG_LV_FATAL, "JT_AUDIT_HTTP_PLUG_INIT", "Register stream label failed ...");
		return -1;
	}

	return 0;
}
void JT_AUDIT_HTTP_PLUG_DESTROY(void)
{

}

