/*
 * Copyright (C) 
 * Copyright (C) 
 * author:      	wu yangping
 * create time:		20120600
 * update time: 	20120727
 */

#ifndef __WHITE_LIST_IS_IN_LIST_
#define	__WHITE_LIST_IS_IN_LIST_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_network_addr_list_s  ngx_network_addr_list_t;

struct ngx_network_addr_list_s {
    void					*data;
	ngx_int_t				delete;
	ngx_network_addr_list_t *next;
};

typedef struct {
    ngx_rbtree_t       		*rbtree;
	ngx_network_addr_list_t	*network_list;
    ngx_str_t           	var;
} ngx_white_black_list_ctx_t;

typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
} ngx_network_addr_node_t;

typedef struct {
    u_char              color;
    u_char              len;
    u_char              data[1];
} ngx_white_black_list_node_t;

typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_uint_t          isvalid;		/*on or off*/
	ngx_uint_t			iswhite;		/*is white list ?*/
	ngx_uint_t			delete;			/*delete flag*/
} ngx_white_black_list_isvalid_t;

typedef struct {
    ngx_array_t         valids;
	ngx_uint_t          log_level;
} ngx_white_black_list_conf_t;

typedef struct {
	ngx_str_t			*conf_type;
	ngx_str_t			*zone_name;
	ngx_str_t			*conf_path;
	ngx_shm_zone_t		*shm_zone;
}ngx_white_black_array_node_t;

extern ngx_array_t         *array_white_black_list;
extern ngx_module_t  		ngx_white_black_list_module;

ngx_int_t ngx_white_list_is_in_list(ngx_http_request_t *r);

ngx_int_t  ngx_white_black_add_item(ngx_http_request_t *r, ngx_str_t *value, ngx_str_t *zone_name, ngx_str_t *reason);
ngx_int_t ngx_white_black_delete_item(ngx_http_request_t *r, ngx_str_t *value, ngx_str_t *zone_name, ngx_str_t *reason);
char *ngx_http_white_black_list_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif
