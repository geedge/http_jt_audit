/*
 *
 * Copyright (c) 2014
 * String Algorithms Research Group
 * Institute of Information Engineering, Chinese Academy of Sciences (IIE-CAS)
 * National Engineering Laboratory for Information Security Technologies (NELIST)
 * All rights reserved
 *
 * Written by:  LIU YANBING (liuyanbing@iie.ac.cn)
				LU YUHAI    (luyuhai@iie.ac.cn)
			  
 * Last modification: 2014-9-22
 *
 * This code is the exclusive and proprietary property of IIE-CAS and NELIST. 
 * Usage for direct or indirect commercial advantage is not allowed without 
 * written permission from the authors.
 *
 */

#ifndef H_DOCUMENT_ANALYZE_H
#define H_DOCUMENT_ANALYZE_H

#ifdef __cplusplus
extern "C"
{
#endif

#define DOC_PRO_OK		0
#define DOC_PRO_ERR		-1

	/* 格式文档类型定义 */
	enum  DocumentType
	{
		DOC_UNKNOWN_TYPE = 0,	/* 未知文档类型 */

		DOC_TXT_TYPE,			/* 纯文本 */

		/* Office 97-2003文档类型 */
		DOC_DOC_TYPE,			/* Word 97-2003 */
		DOC_PPT_TYPE,			/* Powerpoint 97-2003 */
		DOC_XLS_TYPE,			/* Excel 97-2003 */

		/* Office 2007文档类型 */
		DOC_DOCX_TYPE,			/* Word 2007 */
		DOC_PPTX_TYPE,			/* Powerpoint 2007 */
		DOC_XLSX_TYPE,		    /* Excel 2007 */

		/* Open Office文档类型 */
		DOC_ODT_TYPE,			/* ODT格式 */
		DOC_ODS_TYPE,			/* ODS格式 */ 
		DOC_ODP_TYPE,			/* ODP格式 */

		/* iWork文档类型 */
		DOC_PAGES_TYPE,			/* iWork Page */
		DOC_KEY_TYPE,			/* iWork Keynote */
		DOC_NUMBERS_TYPE,		/* iWork Numbers */

		/* 其它常用文档类型 */
		DOC_PDF_TYPE,			/* pdf格式 */
		DOC_EML_TYPE,			/* eml格式 */
		DOC_HTML_TYPE,			/* HTML格式 */
		DOC_CHM_TYPE,			/* chm格式 */
		DOC_RTF_TYPE,			/* rtf格式 */
		DOC_MDB_TYPE,		    /* Microsoft Access数据库文件 */

		/* 压缩文件格式 */
		DOC_ZIP_TYPE,			/* zip格式 */
		DOC_RAR_TYPE,			/* rar格式 */
		DOC_GZIP_TYPE,			/* gzip格式 */
		DOC_BZIP_TYPE,			/* bzip格式 */
		DOC_7Z_TYPE,			/* 7z格式 */
		DOC_DEFLATE_TYPE,		/* deflate格式 */

		/* 图像文件格式 */
		DOC_BMP_TYPE,			/* bmp格式 */
		DOC_GIF_TYPE,			/* gif格式 */
		DOC_JPEG_TYPE,			/* jpeg格式 */
		DOC_RAW_TYPE,			/* raw格式 */
		DOC_EMF_TYPE,			/* emf格式 */
		DOC_WMF_TYPW,			/* wmf格式 */
		DOC_PNG_TYPE,			/* png格式 */
		DOC_PCT_TYPE,			/* pct格式 */
		DOC_PBM_TYPE,			/* pbm格式 */
		DOC_PPM_TYPE,			/* ppm格式 */

		/* 视频文件格式 */
		DOC_MPEG4_TYPE,			/* mpeg4格式 */
		DOC_AV_TYPE,			/* av格式 */
		DOC_3GP_TYPE,			/* 3gp格式 */
		DOC_ASF_TYPE,			/* asf格式 */
		DOC_AVI_TYPE,			/* avi格式 */
		DOC_MKV_TYPE,			/* mkv格式 */
		DOC_MOV_TYPE,			/* mov格式 */
		DOC_MP4_TYPE,			/* mp4格式 */
		DOC_RMVB_TYPE,			/* rmvb格式 */
		DOC_RM_TYPE,			/* rm格式 */
		DOC_WMV_TYPE,			/* wmv格式 */

		/* 音频文件格式 */
		DOC_MP3_TYPE,			/* mp3格式 */
		DOC_WAV_TYPE,			/* wav格式 */
		DOC_WMA_TYPE,			/* wma格式 */
		DOC_AAC_TYPE,			/* aac格式 */
		DOC_OGG_TYPE,			/* ogg格式 */
		DOC_APE_TYPE,			/* ape格式 */
		DOC_FLAC_TYPE,			/* flac格式 */

		/* 可执行文件格式 */
		DOC_PE_TYPE,			/* Windows可执行文件格式，包括：exe、dll、vxd、sys和vdm等 */
		DOC_ELF_TYPE,			/* Linux可执行文件格式 */
	};

	/* 输出文本的编码类型 */
	enum  CodeType
	{
		CODE_UNKNOWN_TYPE = 0,		/* 未知编码 */
		CODE_GBK_TYPE,				/* GBK */
		CODE_BIG5_TYPE,				/* BIG5 */
		CODE_UNICODE_TYPE, 			/* UNICODE */
		CODE_UTF8_TYPE,				/* UTF8 */
		CODE_UTF7_TYPE,				/* UTF7 */
	};

	/* zip等压缩文档或eml中需要使用到的子文档类型 */
	enum DocumentSubType
	{
		DOC_UNKNOW_SUBTYPE = 0,		/* 未知子类型 */
		DOC_FILENAME_SUBTYPE,		/* 子文档的文件名 */
		DOC_CONTENT_SUBTYPE,		/* 子文档的内容 */
	};

	typedef struct _docanalyze_result_t
	{
		char * presult;						/* 数据的内容 */
		int	   size;						/* 数据的长度 */
		enum DocumentType doc_type;			/* 此段数据所属的文档类型 */
		enum DocumentSubType doc_sub_type;	/* 此段数据所属的子文档类型 */
		enum CodeType code_type;			/* 此段数据的当前编码类型 */
	}docanalyze_result_t;

	typedef struct _result_array_t
	{
		int result_num;						/* 结果数组的元素个数 */
		docanalyze_result_t * result_buff;	/* 结果数组 */
	}result_array_t;

	typedef void * docanalyze_instance_t;
	typedef void * docanalyze_streamparam_t;

	/************************格式文档分析相关函数*********************************/
	
	/*
	功能：
		格式文档类型识别，根据文档头部信息识别文档的类型，建议提供的头部数据长度hlen至少64字节。
	参数：
		header	: 文件头；
		hlen 	: 文件头长度；
	返回值：
		识别出的文档类型；无法识别返回 DOC_UNKNOWN_TYPE。
	*/
	enum DocumentType docanalyze_identify(const char * header, unsigned int hlen);

	/*
	功能：
		格式文档分析器的初始化，根据待分析的文档类型创建相应的文档分析器
		以及相应的公用数据结构
	参数：
		doc_type[in]       ：文档类型；
		max_thread_num [in]: 扫描器可并行执行的线程数。
	返回值：
		分档分析器指针，若失败则返回 NULL。
	*/
	docanalyze_instance_t docanalyze_initialize(unsigned int max_thread_num);

	/*
	功能：
		释放每种文档类型的分析器以及相应的公用数据结构
	参数：
		instance[in]：文档分析器句柄
	返回值：
		DOC_PRO_OK  ：正常；
		DOC_PRO_ERR ：失败。
	*/
	int docanalyze_destroy(docanalyze_instance_t instance);

	/*
	功能：
		启动一次流式分档解析，申请保存流状态的参数。
	参数：
		instance  [in]:  文档分析器指针；
		thread_id [in]:  当前执行文档分析的线程id，必须在范围[0, max_thread_num-1]之内。
	返回值：
		返回保存流状态的参数；返回值为NULL时，表示失败。
	 */
	docanalyze_streamparam_t docanalyze_startstream(enum DocumentType doc_type, docanalyze_instance_t instance, unsigned int thread_id);

	/* 
	功能：
		流式文档分析接口，解析一段输入的原始文档数据data，流状态的一些相关中间结果保存在stream_param中，
		解析的结果存放在res中，空间由本函数内部申请,解析结束后需要调用docanalyze_freeresult释放res的内存空间。
	参数：
		stream_param [in]	: 保存流状态的参数；
		data[in]			：待分析的文档数据；
		dlen[in]			：数据长度；
		result_array[out]	：解析的结果。
	返回值：
		DOC_PRO_OK  ：解析正常；
		DOC_PRO_ERR ：解析失败。
	*/
	int docanalyze_parsestream(docanalyze_streamparam_t stream_param, const  char * data, unsigned int dlen, result_array_t * result_array);

	/* 
	功能：
		用户使用完毕后，调用此函数释放结果result_array的内存空间,这个函数需要与docanalyze_parsestream成对使用
	返回值：
		DOC_PRO_OK  ：正常；
		DOC_PRO_ERR ：失败。
	*/
	int docanalyze_freeresult(result_array_t * result_array);

	/*
	功能：结束流式解析，释放流参数。
	参数：
		stream_param [in]: 流参数指针。
	返回值：
		DOC_PRO_OK  ：正常；
		DOC_PRO_ERR ：失败。
	*/ 
	int docanalyze_endstream(docanalyze_streamparam_t stream_param);

#ifdef __cplusplus
}
#endif

#endif /*end of defined H_DOCUMENT_ANALYZE_H*/