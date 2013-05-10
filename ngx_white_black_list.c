/*
 * Copyright (C) 
 * Copyright (C) 
 * author:      	wu yangping
 * create time:		20120600
 * update time: 	20120727
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_white_black_list.h>


ngx_array_t         *array_white_black_list;

static char *ngx_white_black_list_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_white_black_list_handler(ngx_http_request_t *r);
static ngx_int_t ngx_white_only_list_handler(ngx_http_request_t *r);
static ngx_int_t ngx_dyn_black_delete_handler(ngx_http_request_t *r);

static ngx_int_t ngx_white_black_list_init(ngx_conf_t *cf);

static void * ngx_white_black_list_create_conf(ngx_conf_t *cf);
static char * ngx_white_black_list_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_white_black_list_conf_parse (ngx_shm_zone_t *shm_zone);
static char *ngx_http_dyn_black_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_shm_zone_t *ngx_whte_black_get_shmzone_by_name(ngx_str_t *zone_name);


static ngx_command_t  ngx_white_black_list_commands[] = {

    { ngx_string("white_black_list_conf"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_white_black_list_set,
      0,
      0,
      NULL },

	{ ngx_string("white_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_white_black_list_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("black_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_white_black_list_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

	{ ngx_string("dyn_black"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
	  ngx_http_dyn_black_set,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_white_black_list_commands_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_white_black_list_init, 				   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_white_black_list_create_conf,      /* create location configuration */
    ngx_white_black_list_merge_conf 	   /* merge location configuration */
};


ngx_module_t  ngx_white_black_list_module = {
    NGX_MODULE_V1,
    &ngx_white_black_list_commands_ctx,    /* module context */
    ngx_white_black_list_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_rbtree_node_t *
ngx_white_black_list_lookup(ngx_rbtree_t *rbtree, ngx_str_t *vv,
    uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_white_black_list_node_t *lcn;
	ngx_cidr_t 					*cdir;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
		
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (ngx_white_black_list_node_t *) &node->color;
		cdir = (ngx_cidr_t *)&lcn->data;
		rc=cdir->u.in.addr-ngx_inet_addr(vv->data,vv->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static void
ngx_white_black_list_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           	  **p;
    ngx_white_black_list_node_t       *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_white_black_list_node_t *) &node->color;
            lcnt = (ngx_white_black_list_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

	node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    *p = node;
    ngx_rbt_red(node);
}

static ngx_int_t
ngx_white_list_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_white_black_list_ctx_t       *octx = data;

    size_t                      	 len;
    ngx_slab_pool_t                  *shpool;
    ngx_rbtree_node_t                *sentinel;
    ngx_white_black_list_ctx_t  	 *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ngx_strcmp(ctx->var.data, octx->var.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "whilte_black_list zone \"%V\" uses the \"%V\" variable "
                          "while previously it used the \"%V\" variable",
                          &shm_zone->shm.name, &ctx->var, &octx->var);
            return NGX_ERROR;
        }

        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

	ctx->network_list = ngx_slab_alloc(shpool, sizeof(ngx_network_addr_list_t));
	if (ctx->network_list == NULL)
		return NGX_ERROR;

	ctx->network_list->data = NULL;
	ctx->network_list->delete= 0;
	ctx->network_list->next = NULL;
	
    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_white_black_list_rbtree_insert_value);

    len = sizeof(" in whilte_black_list zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in whilte_black_list zone \"%V\"%Z",
                &shm_zone->shm.name);

	return ngx_white_black_list_conf_parse(shm_zone);
    return NGX_OK;
}

static char *
ngx_white_black_list_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                     		*p;
    ssize_t                     	size;
    ngx_str_t                  		*value, name, s;
    ngx_uint_t                  	i;
    ngx_shm_zone_t             		*shm_zone;
    ngx_white_black_list_ctx_t 		*ctx;
	ngx_white_black_array_node_t	*ngx_wb_array_node;

	value = cf->args->elts;
    ctx = NULL;
    size = 0;
    name.len = 0;

	if (array_white_black_list == NULL){
		array_white_black_list = ngx_array_create(cf->pool, 8, sizeof(ngx_white_black_array_node_t));
		if (array_white_black_list == NULL){
			return NGX_CONF_ERROR;
		}
	}
	
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
		
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_white_black_list_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}
	
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

	ctx->var.data = value[1].data;
	ctx->var.len = value[1].len;
	
	if (ngx_conf_full_name(cf->cycle, &ctx->var, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_white_black_list_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to variable \"%V\"",
                           &cmd->name, &name, &ctx->var);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_white_list_init_zone;
    shm_zone->data = ctx;
	
	ngx_wb_array_node = ngx_array_push(array_white_black_list);
	if(ngx_wb_array_node == NULL){
		return NGX_CONF_ERROR;
	}
	
	ngx_wb_array_node->zone_name = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (ngx_wb_array_node->zone_name == NULL){
		return NGX_CONF_ERROR;
	}

	ngx_wb_array_node->conf_path= ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (ngx_wb_array_node->conf_path== NULL){
		return NGX_CONF_ERROR;
	}

	ngx_wb_array_node->conf_type= ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (ngx_wb_array_node->conf_type== NULL){
		return NGX_CONF_ERROR;
	}
	
	ngx_wb_array_node->shm_zone = shm_zone;
	ngx_wb_array_node->zone_name->data = name.data;
	ngx_wb_array_node->zone_name->len = name.len;
	ngx_wb_array_node->conf_path->data = value[1].data;
	ngx_wb_array_node->conf_path->len = value[1].len;
	ngx_wb_array_node->conf_type->data = value[0].data;
	ngx_wb_array_node->conf_type->len = value[0].len;
	
	if (ngx_conf_full_name(cf->cycle, ngx_wb_array_node->conf_path, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
	return NGX_CONF_OK;
}

static
ngx_int_t ngx_white_black_list_conf_parse (ngx_shm_zone_t *shm_zone)
{
	off_t							file_size;
	ssize_t							n,len;
	uint32_t                        hash;
	ngx_fd_t						fd;
	ngx_str_t						*value, ip_value;
	ngx_buf_t						buf;
	ngx_conf_file_t					file;
	ngx_slab_pool_t     			*shpool;
	ngx_rbtree_node_t               *node;
	ngx_white_black_list_ctx_t      *ctx;
    ngx_white_black_list_node_t     *lc;
	ngx_network_addr_list_t			*pos_net_addr, *new_node;
	ngx_network_addr_node_t			*pos_net_data;
	ngx_cidr_t 						cdir;

	if (shm_zone == NULL)
		return NGX_ERROR;

	ctx = shm_zone->data;
	value = &ctx->var;
	
	shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
	
	fd = ngx_open_file(value->data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN, 0);
	if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, ngx_errno,
                           ngx_open_file_n " \"%s\" failed",
                           value->data);
        return NGX_ERROR;
    }
	
	if (ngx_fd_info(fd, &file.file.info) == -1) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", value->data);
    }

	file.buffer = &buf;
	file.file.fd = fd;
	file.file.name.data = value->data;
	file.file.name.len = value->len;
	file.file.log = shm_zone->shm.log;
	file.file.offset = 0;
	file.line = 1;

	file_size = ngx_file_size(&file.file.info);

	buf.start = ngx_alloc(file_size, shm_zone->shm.log);
    if (buf.start == NULL) {
        goto failed;
    }

    buf.pos = buf.start;
    buf.last = buf.start;
    buf.end = buf.last + file_size;
    buf.temporary = 1;

	n = ngx_read_file(&file.file, buf.start, file_size,
                          file.file.offset);

	if (n == NGX_ERROR)
	{
		ngx_free(buf.start);
		goto failed;
	}
	
	/*you can parse file now!*/

	ngx_shmtx_lock(&shpool->mutex);
	for (buf.pos = buf.start ;buf.pos < buf.end; buf.pos++)
	{	
		/*skip the line that start with '#'!*/
		if (*buf.pos == '#')
		{
			for (;buf.pos < buf.end; buf.pos++)
			{
				if (*buf.pos == '\n' || (*buf.pos == CR && *(buf.pos+1)==LF))
					break;
			}
		}

		/*skip*/
		if (*buf.pos == '\n' || *buf.pos == ' ' 
		 || *buf.pos == '\t' || *buf.pos == CR || *buf.pos == LF)
		{
			continue;
		}

		buf.last = buf.pos;
		ip_value.data = buf.pos;
		
		for (;buf.pos < buf.end; buf.pos++)
		{
			if (*buf.pos == '\n' || (*buf.pos == CR && *(buf.pos+1)==LF))
			{
				buf.last = buf.pos;
				break;
			}
		}

		if (buf.last == ip_value.data)
		{
			/*last line?*/
			if (buf.end - buf.pos < 19 /*sizeof("255.255.255.255/32")+1*/)
			{
				buf.last = buf.end;
			}
			else
			{
				continue;
			}
		}

		ip_value.len = buf.last - ip_value.data;

		if (ip_value.len > 18)
		{
			ngx_log_error(NGX_LOG_ALERT, shm_zone->shm.log, 0,
                          "zone name %s, the value of the %s, "
                          "is more than 18 bytes! ABORT!!!"
                          , shm_zone->shm.name.data, ip_value.data);	
			continue;
		}
		
		len = sizeof(ngx_cidr_t);
		
		if (ngx_ptocidr(&ip_value, &cdir) == NGX_ERROR)
		{
			ngx_shmtx_unlock(&shpool->mutex);
			
			ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0,
                          "ngx_ptocidr error in ngx_white_black_list_conf_parse, zone_name:%s, ipvalue:%s, start failed!"
                          , shm_zone->shm.name.data, ip_value.data);	
			ngx_free(buf.start);
			goto failed;
		}

		shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
		/*is network addr*/
		if (cdir.u.in.mask != 0xffffffff)
		{
			pos_net_addr = ctx->network_list;
			if (pos_net_addr->data == NULL)
			{
				pos_net_data = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_node_t));
				if (pos_net_data == NULL)
					return NGX_ERROR;

				pos_net_data->addr = cdir.u.in.addr;
				pos_net_data->mask = cdir.u.in.mask;
				pos_net_addr->data = pos_net_data;
				continue;
			}

			for (;pos_net_addr->next!=NULL; pos_net_addr = pos_net_addr->next){
			}

			new_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_list_t));
			if (new_node == NULL)
				return NGX_ERROR;
			pos_net_data = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_node_t));
			if (pos_net_data == NULL)
				return NGX_ERROR;
			
			pos_net_data->addr = cdir.u.in.addr;
			pos_net_data->mask = cdir.u.in.mask;
			new_node->data = pos_net_data;
			new_node->delete = 0;
			new_node->next = NULL;
			pos_net_addr->next = new_node;
			continue;
		}
		
		hash = (uint32_t)cdir.u.in.addr;
		
		n = offsetof(ngx_rbtree_node_t, color)
	        + offsetof(ngx_white_black_list_node_t, data)
	        + len;

	    node = ngx_slab_alloc_locked(shpool, n);

	    if (node == NULL) {
	        ngx_shmtx_unlock(&shpool->mutex);
			ngx_free(buf.start);
	        goto failed;
	    }

	    lc = (ngx_white_black_list_node_t *) &node->color;

	    node->key = hash;
	    lc->len = (u_char) len;
	    ngx_memcpy(lc->data, &cdir, len);

		ngx_rbtree_insert(ctx->rbtree, node);
	}
	ngx_shmtx_unlock(&shpool->mutex);

	if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, shm_zone->shm.log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          value->data);
            return NGX_ERROR;
    }
	return NGX_OK;
	
failed:
	if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, shm_zone->shm.log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          value->data);
            return NGX_ERROR;
    }

    return NGX_ERROR;
}

static
char * ngx_white_black_list_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	/*init shm*/
	if (ngx_white_black_list_zone(cf, cmd, conf) == NGX_CONF_ERROR)
		return NGX_CONF_ERROR;

	return NGX_CONF_OK;
}

ngx_int_t ngx_white_list_is_in_list(ngx_http_request_t *r)
{
	/*if return NGX_OK then the remote_ip in white_list!*/
	if (ngx_white_only_list_handler(r) == NGX_OK)
		return NGX_OK;
	return NGX_ERROR;
}

static ngx_int_t
ngx_ip_in_black_list(ngx_http_request_t *r)
{
	uint32_t                        hash;
	ngx_str_t						*ip_str;
	ngx_uint_t						i;
	ngx_slab_pool_t              	*shpool;
	ngx_rbtree_node_t              *node;
	ngx_network_addr_list_t			*pos_net_addr;
	ngx_network_addr_node_t			*pos_data;
	ngx_white_black_list_ctx_t      *ctx;
	ngx_white_black_list_node_t		*bln;
	ngx_white_black_list_conf_t  	*lccf;
	ngx_white_black_list_isvalid_t 	*valids;

	ip_str = &r->connection->addr_text;
	hash = (uint32_t)ngx_inet_addr(ip_str->data, ip_str->len);

	lccf = ngx_http_get_module_loc_conf(r, ngx_white_black_list_module);
	valids = lccf->valids.elts;

	/*black list*/
	for (i = 0; i < lccf->valids.nelts; i++) {

		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;

		if (valids[i].iswhite)
			continue;

		if (valids[i].delete == 1)
			continue;

		shpool = (ngx_slab_pool_t *)valids[i].shm_zone->shm.addr;
		ctx = (ngx_white_black_list_ctx_t *)valids[i].shm_zone->data;
		if (shpool == NULL || ctx == NULL)
			continue;

		ngx_shmtx_lock(&shpool->mutex);
		node = ngx_white_black_list_lookup(ctx->rbtree, ip_str, hash);
		ngx_shmtx_unlock(&shpool->mutex);
		if (node)
		{
			return NGX_OK;
		}
	}
	return NGX_ERROR;
}

static ngx_int_t 
ngx_dyn_black_delete_handler(ngx_http_request_t *r)
{
	uint32_t                        hash;
	ngx_str_t						*ip_str;
	ngx_uint_t						i;
	ngx_slab_pool_t              	*shpool;
	ngx_rbtree_node_t              *node;
	ngx_network_addr_list_t			*pos_net_addr;
	ngx_network_addr_node_t			*pos_data;
	ngx_white_black_list_ctx_t      *ctx;
	ngx_white_black_list_node_t		*bln;
	ngx_white_black_list_conf_t  	*lccf;
	ngx_white_black_list_isvalid_t 	*valids;

	if (r==NULL || r->connection==NULL)
			return NGX_DECLINED;

	ip_str = &r->connection->addr_text;
	hash = (uint32_t)ngx_inet_addr(ip_str->data, ip_str->len);

	lccf = ngx_http_get_module_loc_conf(r, ngx_white_black_list_module);
	valids = lccf->valids.elts;

	/*black list*/
	for (i = 0; i < lccf->valids.nelts; i++) {

		/*
		 * dyn_black enable?
		 * */
		if (!valids[i].is_dyn_black)
			continue;

		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;

		if (valids[i].iswhite)
			continue;

		if (valids[i].delete == 1)
			continue;

		/*==0 ËµÃ÷ÎªÓÀ¾Ã*/
		if (valids[i].forbidden_time == 0)
			continue;

		shpool = (ngx_slab_pool_t *)valids[i].shm_zone->shm.addr;
		ctx = (ngx_white_black_list_ctx_t *)valids[i].shm_zone->data;
		if (shpool == NULL || ctx == NULL)
			continue;

		ngx_shmtx_lock(&shpool->mutex);
		node = ngx_white_black_list_lookup(ctx->rbtree, ip_str, hash);
		ngx_shmtx_unlock(&shpool->mutex);
		if (node)
		{
			bln = (ngx_white_black_list_node_t *) &node->color;
			if (bln->is_dyn_black)
			{
				/*delete*/
				if (bln->add_time + valids[i].forbidden_time < ngx_cached_time->sec)
				{
					ngx_shmtx_lock(&shpool->mutex);
					ngx_rbtree_delete(ctx->rbtree, node);
					ngx_shmtx_unlock(&shpool->mutex);

					return NGX_DECLINED;;
				}
			}
		}
	}
	return NGX_DECLINED;
}

static ngx_int_t
ngx_white_black_list_handler(ngx_http_request_t *r)
{
	uint32_t                        hash;
	ngx_str_t						*ip_str;
	ngx_uint_t						i;
	ngx_slab_pool_t              	*shpool;
	ngx_rbtree_node_t              *node;
	ngx_network_addr_list_t			*pos_net_addr;
	ngx_network_addr_node_t			*pos_data;
	ngx_white_black_list_ctx_t      *ctx;
	ngx_white_black_list_conf_t  	*lccf;
	ngx_white_black_list_isvalid_t 	*valids;
	

	if (r==NULL || r->connection==NULL)
		return NGX_DECLINED;

	ip_str = &r->connection->addr_text;
	hash = (uint32_t)ngx_inet_addr(ip_str->data, ip_str->len);
	
	lccf = ngx_http_get_module_loc_conf(r, ngx_white_black_list_module);
    valids = lccf->valids.elts;

	/*black list*/
	for (i = 0; i < lccf->valids.nelts; i++) {
		
		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;
		
		if (valids[i].iswhite)
			continue;

		if (valids[i].delete == 1)
			continue;
		
		shpool = (ngx_slab_pool_t *)valids[i].shm_zone->shm.addr;
		ctx = (ngx_white_black_list_ctx_t *)valids[i].shm_zone->data;
		
		/*ngx_shmtx_lock(&shpool->mutex);*/
		node = ngx_white_black_list_lookup(ctx->rbtree, ip_str, hash);
		/*ngx_shmtx_unlock(&shpool->mutex);*/
		if (node)
			return NGX_HTTP_FORBIDDEN;

		/*in network list?*/
		pos_net_addr = ctx->network_list;
		for (;pos_net_addr!=NULL;
			pos_net_addr = pos_net_addr->next)
		{
			if (pos_net_addr->data!=NULL
				&& pos_net_addr->delete != 1)
			{
				pos_data = pos_net_addr->data;
				if ((pos_data->mask & hash)
					== pos_data->addr)
					return NGX_HTTP_FORBIDDEN;
			}
		}
	}

	/*white list*/
	for (i = 0; i < lccf->valids.nelts; i++) {
		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;

		if (!valids[i].iswhite)
			continue;

		if (valids[i].delete == 1)
			continue;
		
		ctx = (ngx_white_black_list_ctx_t *)valids[i].shm_zone->data;
		shpool = (ngx_slab_pool_t *)valids[i].shm_zone->shm.addr;

		/*ngx_shmtx_lock(&shpool->mutex);*/
		node = ngx_white_black_list_lookup(ctx->rbtree, ip_str, hash);
		/*ngx_shmtx_unlock(&shpool->mutex);*/
		if (node)
			return NGX_OK;
		
		/*in network list?*/
		pos_net_addr = ctx->network_list;
		for (;pos_net_addr!=NULL;
			pos_net_addr = pos_net_addr->next)
		{
			if (pos_net_addr->data!=NULL
				&& pos_net_addr->delete != 1)
			{
				pos_data = pos_net_addr->data;
				if ((pos_data->mask & hash)
					== pos_data->addr)
					return NGX_OK;
			}
		}
	}

	return NGX_DECLINED;
}


static ngx_int_t 
ngx_white_only_list_handler(ngx_http_request_t *r)
{
	uint32_t                        hash;
	ngx_str_t						*ip_str;
	ngx_uint_t						i;
	ngx_slab_pool_t                *shpool;
	ngx_rbtree_node_t             	*node;
	ngx_network_addr_node_t			*pos_data;
	ngx_network_addr_list_t			*pos_net_addr;
	ngx_white_black_list_ctx_t      *ctx;
	ngx_white_black_list_conf_t  	*lccf;
	ngx_white_black_list_isvalid_t 	*valids;
							

	if (r==NULL || r->connection==NULL)
		return NGX_DECLINED;

	ip_str = &r->connection->addr_text;
	hash = (uint32_t)ngx_inet_addr(ip_str->data, ip_str->len);
	
	lccf = ngx_http_get_module_loc_conf(r, ngx_white_black_list_module);
    valids = lccf->valids.elts;

	/*white list*/
	for (i = 0; i < lccf->valids.nelts; i++) {
		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;

		if (!valids[i].iswhite)
			continue;

		if (valids[i].delete ==1 )
			continue;
		
		ctx = (ngx_white_black_list_ctx_t *)valids[i].shm_zone->data;
		shpool = (ngx_slab_pool_t *)valids[i].shm_zone->shm.addr;

		/*ngx_shmtx_lock(&shpool->mutex);*/
		node = ngx_white_black_list_lookup(ctx->rbtree, ip_str, hash);
		/*ngx_shmtx_unlock(&shpool->mutex);*/
		if (node)
			return NGX_OK;
		
		/*in network list?*/
		pos_net_addr = ctx->network_list;
		for (;pos_net_addr!=NULL;
			pos_net_addr = pos_net_addr->next)
		{
			if (pos_net_addr->data!=NULL
				&& pos_net_addr->delete != 1)
			{
				pos_data = pos_net_addr->data;
				if ((pos_data->mask & hash)
					== pos_data->addr)
					return NGX_OK;
			}
		}
	}

	return NGX_DECLINED;
}

static ngx_int_t
ngx_white_black_list_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_white_black_list_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
	    return NGX_ERROR;
    }

    *h = ngx_dyn_black_delete_handler;

    return NGX_OK;
}

static void *
ngx_white_black_list_create_conf(ngx_conf_t *cf)
{
    ngx_white_black_list_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_white_black_list_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->isvalid.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_white_black_list_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_white_black_list_conf_t *prev = parent;
    ngx_white_black_list_conf_t *conf = child;

    if (conf->valids.elts == NULL) {
        conf->valids= prev->valids;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);

    return NGX_CONF_OK;
}

static char *ngx_http_dyn_black_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t                       *value;
	ngx_uint_t                      i;
	ngx_shm_zone_t              	*shm_zone;
	ngx_white_black_list_conf_t  	*lccf = conf;
	ngx_white_black_list_isvalid_t 	*valid, *valids;

	value = cf->args->elts;

	if (cf->args->nelts < 3)
			return NGX_CONF_ERROR;

	shm_zone = ngx_whte_black_get_shmzone_by_name(&value[1]);
	//shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
	//                                    &ngx_white_black_list_module);

	if (shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	valids = lccf->valids.elts;
	if (valids == NULL) {
		if (ngx_array_init(&lccf->valids, cf->pool, 1,
						   sizeof(ngx_white_black_list_isvalid_t))
			!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
	}

	for (i = 0; i < lccf->valids.nelts; i++) {
		if (valids[i].shm_zone == shm_zone)
		{
			valids[i].is_dyn_black = 1;
			valids[i].forbidden_time = ngx_atoi(value[2].data, value[2].len);
		}

		break;
	}

	return NGX_CONF_OK;
}

char *ngx_http_white_black_list_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_uint_t                      i;
    ngx_shm_zone_t              	*shm_zone;
    ngx_white_black_list_conf_t  	*lccf = conf;
    ngx_white_black_list_isvalid_t 	*valid, *valids;

    value = cf->args->elts;

    if (cf->args->nelts < 3)
            return NGX_CONF_ERROR;

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_white_black_list_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    valids = lccf->valids.elts;

    if (valids == NULL) {
        if (ngx_array_init(&lccf->valids, cf->pool, 1,
                           sizeof(ngx_white_black_list_isvalid_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->valids.nelts; i++) {
		if (valids[i].iswhite &&
				ngx_memcmp(value[0].data, "white_list", value[0].len)!=0)
			continue;

		if (!valids[i].iswhite &&
				ngx_memcmp(value[0].data, "black_list", value[0].len)!=0)
			continue;

        if (shm_zone == valids[i].shm_zone) {
			/*update conf*/
			valids[i].isvalid = 0;
			if (ngx_memcmp(value[2].data, "on", value[2].len)==0)
				valids[i].isvalid= 1;

			valids[i].iswhite = 1;
			
			if (ngx_memcmp(value[0].data,"black_list", value[0].len)==0)
				valids[i].iswhite= 0;
		    valids[i].shm_zone = shm_zone;
			valids[i].delete =0;
			
			valids[i].is_dyn_black = 0;

            return NGX_CONF_OK;
        }
    }

    valid = ngx_array_push(&lccf->valids);
	if (valid == NULL)
		return NGX_CONF_ERROR;
	
	valid->isvalid = 0;
	if (ngx_memcmp(value[2].data, "on", value[2].len)==0)
		valid->isvalid= 1;

	valid->iswhite = 1;
	
	if (ngx_memcmp(value[0].data,"black_list", value[0].len)==0)
		valid->iswhite= 0;
    valid->shm_zone = shm_zone;
	valid->delete =0;

    return NGX_CONF_OK;
}

ngx_shm_zone_t *ngx_whte_black_get_shmzone_by_name(ngx_str_t *zone_name)
{
	ngx_uint_t 						n;
	ngx_shm_zone_t					*shm_zone = NULL;
	ngx_white_black_array_node_t 	*wb_array_node;
	
	if (zone_name ==NULL)
		return NULL;
	
	if (array_white_black_list)
	{
		wb_array_node = array_white_black_list->elts;
		for (n=0; n<array_white_black_list->nelts; n++)
		{
			if (ngx_memcmp(zone_name->data, wb_array_node[n].zone_name->data, wb_array_node[n].zone_name->len)==0)
			{
				shm_zone = wb_array_node[n].shm_zone;
				break;
			}
		}
	}
	
	return shm_zone;
}

ngx_int_t ngx_is_network_addr(ngx_str_t *v)
{
	size_t		n;

	if (v == NULL)
		return NGX_ERROR;
	
	for (n=0; n < v->len; n++)
	{
		if (v->data[n] == '/')
			return NGX_OK;
	}
	
	return NGX_ERROR;
}

ngx_int_t ngx_white_black_write_to_file(ngx_str_t *value, ngx_str_t *zone_name)
{
	u_char							*buf, *pos;
	ngx_str_t						*conf_path = NULL;
	ngx_uint_t 						n;
	ngx_file_t						ngx_file;
	struct stat						sb;
	ngx_white_black_array_node_t 	*wb_array_node;
	

	if (value == NULL || zone_name ==NULL)
		return NGX_ERROR;
	
	if (array_white_black_list)
	{
		wb_array_node = array_white_black_list->elts;
		for (n=0; n<array_white_black_list->nelts; n++)
		{
			if (ngx_memcmp(zone_name->data, wb_array_node[n].zone_name->data, wb_array_node[n].zone_name->len)==0)
			{
				conf_path = wb_array_node[n].conf_path;
				break;
			}
		}
	}

	if (conf_path == NULL)
		return NGX_ERROR;

	ngx_file.name.data = conf_path->data;
	ngx_file.name.len = conf_path->len;

	ngx_file.fd = ngx_open_file(ngx_file.name.data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (ngx_file.fd == NGX_INVALID_FILE)
		return NGX_ERROR;
	
	ngx_fd_info(ngx_file.fd, &sb);
	n = sb.st_size;

	buf = malloc(n);
	if (buf == NULL)
		return NGX_ERROR;
	
	ngx_memset(buf, 0, n);
	if (ngx_read_fd(ngx_file.fd, buf, n) == -1)
	{
		ngx_free(buf);
		ngx_close_file(ngx_file.fd);
		return NGX_ERROR;
	}

	ngx_close_file(ngx_file.fd);
	pos = buf;
	while (pos <buf+n)
	{
		if (ngx_memcmp(pos, value->data, value->len)==0)
		{
			pos += value->len;
			if (*pos == '\n' || *pos == ' ' 
		 	|| *pos == '\t' || *pos == CR || *pos == LF
		 	|| pos >= buf+n)
			{
				ngx_free(buf);
				return NGX_DONE;
			}
		}
		
		pos++;
	}

	ngx_free(buf);
	
	/**/
	ngx_file.fd = ngx_open_file(ngx_file.name.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (ngx_file.fd == NGX_INVALID_FILE)
		return NGX_ERROR;

	if (ngx_write_fd(ngx_file.fd, value->data, value->len) != -1)
	{
		ngx_write_fd(ngx_file.fd, "\n", 1);
		ngx_close_file(ngx_file.fd);
		return NGX_OK;
	}
	
	ngx_close_file(ngx_file.fd);
	return NGX_ERROR;
}

ngx_int_t ngx_white_black_delete_from_file(ngx_str_t *value, ngx_str_t *zone_name)
{
	u_char							*buf, *pos, *end;
	ngx_str_t						*conf_path = NULL;
	ngx_uint_t 						n;
	ngx_file_t						ngx_file;
	struct stat						sb;
	ngx_white_black_array_node_t	*wb_array_node;
	
	
	if (value == NULL || zone_name ==NULL)
		return NGX_ERROR;
	
	if (array_white_black_list)
	{
		wb_array_node = array_white_black_list->elts;
		for (n=0; n<array_white_black_list->nelts; n++)
		{
			if (ngx_memcmp(zone_name->data, wb_array_node[n].zone_name->data, wb_array_node[n].zone_name->len)==0)
			{
				conf_path = wb_array_node[n].conf_path;
				break;
			}
		}
	}

	if (conf_path == NULL)
		return NGX_ERROR;

	ngx_file.name.data = conf_path->data;
	ngx_file.name.len = conf_path->len;
	
	ngx_file.fd = ngx_open_file(ngx_file.name.data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (ngx_file.fd == NGX_INVALID_FILE)
		return NGX_ERROR;
	
	ngx_fd_info(ngx_file.fd, &sb);
	n = sb.st_size;

	buf = malloc(n);
	if (buf == NULL)
		return NGX_ERROR;
	
	ngx_memset(buf, 0, n);
	if (ngx_read_fd(ngx_file.fd, buf, n) == -1)
	{
		ngx_free(buf);
		ngx_close_file(ngx_file.fd);
		return NGX_ERROR;
	}

	ngx_close_file(ngx_file.fd);
	ngx_delete_file(conf_path->data);
	
	ngx_file.fd = ngx_open_file(ngx_file.name.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (ngx_file.fd == NGX_INVALID_FILE)
		return NGX_ERROR;

	pos = buf;
	while (pos < buf+n)
	{
		if (*pos == '#')
		{
			end = pos;
			for (;end < buf+n; end++)
			{
				if (*end == '\n')
				{
					end++;
					ngx_write_fd(ngx_file.fd, pos, end-pos);
					pos=end;
					break;
				}
				else
				if (*end == CR && *(end+1)==LF)
				{
					end+=2;
					ngx_write_fd(ngx_file.fd, pos, end-pos);
					pos = end;
					break;
				}
			}
		}
		
		if (*pos == '\n' || *pos == ' ' 
		 || *pos == '\t' || *pos == CR || *pos == LF)
		{
			ngx_write_fd(ngx_file.fd, pos, 1);
			pos++;
			continue;
		}
		
		if (ngx_memcmp(pos, value->data, value->len) == 0)
		{
			pos = pos+value->len;
			if (*pos == '\n' || *pos == ' ' 
		 		|| *pos == '\t' || *pos == CR || *pos == LF)
			{
				pos++;
				continue;
			}
			else{
				pos = pos-value->len;
			}
		}
		
		ngx_write_fd(ngx_file.fd, pos, 1);
		pos++;
	}

	ngx_free(buf);
	ngx_close_file(ngx_file.fd);

	return NGX_OK;
}

ngx_int_t ngx_black_add_item_interface(ngx_http_request_t *r, u_char is_dyn_black)
{
	ngx_str_t						sr;
	ngx_uint_t						i;
	ngx_white_black_list_conf_t  	*lccf;
	ngx_white_black_list_isvalid_t 	*valids;

	lccf = ngx_http_get_module_loc_conf(r, ngx_white_black_list_module);
	valids = lccf->valids.elts;

	if (r == NULL || r->connection == NULL)
		return NGX_ERROR;

	/*black list*/
	for (i = 0; i < lccf->valids.nelts; i++) {

		if (!valids[i].is_dyn_black && is_dyn_black)
			continue;

		if (valids[i].shm_zone == NULL)
			continue;

		if (valids[i].isvalid == 0)
			continue;

		if (valids[i].iswhite)
			continue;

		if (valids[i].delete == 1)
			continue;

		if (valids[i].shm_zone != NULL)
			return ngx_white_black_add_item(r, &r->connection->addr_text,
							&valids[i].shm_zone->shm.name, &sr, is_dyn_black);
	}

	return NGX_ERROR;
}

ngx_int_t ngx_white_black_add_item(ngx_http_request_t *r, ngx_str_t *value, ngx_str_t *zone_name, ngx_str_t *reason, u_char is_dyn_black)
{
	ssize_t							len, n;
	uint32_t						hash;
	ngx_int_t						rv;
	ngx_cidr_t						cdir;
	ngx_slab_pool_t     			*shpool = NULL;
	ngx_rbtree_node_t               *node;
	ngx_white_black_list_ctx_t      *ctx;
	ngx_network_addr_list_t			*pos_network_addr_list, *new_net_addr;
	ngx_network_addr_node_t			*network_addr_data;
	ngx_shm_zone_t					*shm_zone;
    ngx_white_black_list_node_t     *lc;
	u_char							*buf_temp=NULL, *t=NULL;

	buf_temp = ngx_pcalloc(r->pool,128);
	if (ngx_ip_in_black_list(r) == NGX_OK)
	{
		reason->data = "the ip is exist!";
		reason->len = sizeof("the ip is exist!")-1;
		return NGX_OK;
	}

	t = ngx_pcalloc(r->pool, value->len+1);
	if (buf_temp == NULL
	   ||t == NULL )
	{
		return NGX_ERROR;
	}

	ngx_memcpy(t, value->data, value->len);
	
	if (   value == NULL || zone_name ==NULL 
		|| value->len==0 || zone_name->len==0)
	{
		reason->data = "add_item or zone_name is NULL!";
		reason->len = sizeof("add_item or zone_name is NULL!")-1;
		return NGX_ERROR;
	}
	
	shm_zone = ngx_whte_black_get_shmzone_by_name(zone_name);

	if (shm_zone == NULL)
		return NGX_ERROR;

	shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
	if (shpool == NULL)
		return NGX_ERROR;
		
	len = sizeof(ngx_cidr_t);
	if (ngx_ptocidr(value, &cdir) == NGX_ERROR)
	{
		snprintf(buf_temp, 256, "ngx_ptocidr is failed! the ip=%s .", value->data);
		reason->data = buf_temp;
		reason->len = ngx_strlen(buf_temp);
		return NGX_ERROR;
	}
	
	hash = (uint32_t)cdir.u.in.addr;
	n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_white_black_list_node_t, data)
        + len;
	
    node = ngx_slab_alloc_locked(shpool, n);
    if (node == NULL) {
        return NGX_ERROR;
    }

	ctx = shm_zone->data;
    lc = (ngx_white_black_list_node_t *) &node->color;

    node->key = hash;
    lc->len = (u_char) len;
    lc->is_dyn_black = is_dyn_black;
    lc->add_time = ngx_cached_time->sec;
    ngx_memcpy(lc->data, &cdir, len);

	/*is network addr?*/
	if (ngx_is_network_addr(value) == NGX_OK)
	{
		pos_network_addr_list = ctx->network_list;
		if (pos_network_addr_list==NULL)
			return NGX_ERROR;
		
		if (pos_network_addr_list->data == NULL || pos_network_addr_list->delete == 1)
		{
			if (pos_network_addr_list->delete == 0)
			{
				network_addr_data = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_node_t));
				if (network_addr_data == NULL)
					return NGX_ERROR;
			}
			else
			{
				network_addr_data = pos_network_addr_list->data;
			}
			
			/*data*/
			if (ngx_ptocidr(value, &cdir) == NGX_ERROR)
				return NGX_ERROR;
			network_addr_data->addr = cdir.u.in.addr;
			network_addr_data->mask = cdir.u.in.mask;
			pos_network_addr_list->data = network_addr_data;
		}
		else /*add new node or use old node*/
		{
			if (ngx_ptocidr(value, &cdir) == NGX_ERROR)
				return NGX_ERROR;

			/*is exist?*/
			for (;pos_network_addr_list!=NULL;pos_network_addr_list = pos_network_addr_list->next){
				network_addr_data = pos_network_addr_list->data;
				if (network_addr_data == NULL)
					continue;
				
				if (pos_network_addr_list->delete!=1
					&& ((cdir.u.in.addr & network_addr_data->mask)
					== network_addr_data->addr)
					)
				{
					snprintf(buf_temp, 256, "the ip %s is exist or be included!", t);
					reason->data = buf_temp;
					reason->len = ngx_strlen(buf_temp);
					return NGX_ERROR;
				}
			}
			
			for (pos_network_addr_list = ctx->network_list;
				pos_network_addr_list->next!=NULL && pos_network_addr_list->delete!=1; 
				pos_network_addr_list = pos_network_addr_list->next){
				
			}

			/*need add new node?*/
			if (pos_network_addr_list->next == NULL && pos_network_addr_list->delete!=1){
				new_net_addr = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_list_t));
				if (new_net_addr == NULL)
					return NGX_ERROR;
				network_addr_data = ngx_slab_alloc_locked(shpool, sizeof(ngx_network_addr_node_t));
				if (network_addr_data == NULL)
					return NGX_ERROR;
				/*data*/
				network_addr_data->addr = cdir.u.in.addr;
				network_addr_data->mask = cdir.u.in.mask;
				new_net_addr->delete = 0;
				new_net_addr->data = network_addr_data;
				new_net_addr->next = NULL;
				pos_network_addr_list->next = new_net_addr;
			}
			else
			{
				pos_network_addr_list->delete = 0;
				network_addr_data = pos_network_addr_list->data;
				network_addr_data->addr = cdir.u.in.addr;
				network_addr_data->mask = cdir.u.in.mask;
			}
			
		}

		rv = NGX_OK;
		if (!is_dyn_black)
		{
			rv = ngx_white_black_write_to_file(value, zone_name);
		}

		return rv;
	}

	/*is ip*/
	rv = NGX_OK;
	if (!is_dyn_black)
	{
		rv = ngx_white_black_write_to_file(value, zone_name);
	}

	if (rv != NGX_OK)
	{
		if (rv == NGX_ERROR)
			snprintf(buf_temp, 256, "ngx_white_black_write_to_file failed! the ip=%s  the zone_name=%s.", t, zone_name->data);

		if (rv == NGX_DONE)
			snprintf(buf_temp, 256, "the ip %s is exist", t);
		reason->data = buf_temp;
		reason->len = ngx_strlen(buf_temp);
		return NGX_ERROR;
	}
	
	ngx_shmtx_lock(&shpool->mutex);
	ngx_rbtree_insert(ctx->rbtree, node);
	ngx_shmtx_unlock(&shpool->mutex);
	
	return NGX_OK;
}

ngx_int_t ngx_white_black_delete_item(ngx_http_request_t *r, ngx_str_t *value, ngx_str_t *zone_name, ngx_str_t *reason)
{
	uint32_t						hash;
	ngx_cidr_t						cdir;
	ngx_slab_pool_t     			*shpool = NULL;
	ngx_shm_zone_t					*shm_zone;
	ngx_rbtree_node_t               *node;
	ngx_white_black_list_ctx_t      *ctx;
	u_char							*buf_temp=NULL;
	ngx_network_addr_list_t			*pos_network_addr_list;
	ngx_network_addr_node_t			*network_addr_data;
	
	buf_temp = ngx_pnalloc(r->pool,256);
	
	if (   value == NULL || zone_name ==NULL 
		|| value->len==0 || zone_name->len==0)
	{
		reason->data = "add_item or zone_name is NULL!";
		reason->len = ngx_strlen("add_item or zone_name is NULL!");
		return NGX_ERROR;
	}
	
	shm_zone = ngx_whte_black_get_shmzone_by_name(zone_name);

	if (shm_zone == NULL)
		return NGX_ERROR;

	shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
	if (shpool == NULL)
		return NGX_ERROR;
	
	hash = (uint32_t)ngx_inet_addr(value->data, value->len);
	ctx = shm_zone->data;

	/*is network addr?*/
	if (ngx_is_network_addr(value) == NGX_OK)
	{
		if (ngx_ptocidr(value, &cdir) == NGX_ERROR)
		{
			snprintf(buf_temp, 256, "call ngx_ptocidr error, %s", value->data);
			reason->data = buf_temp;
			reason->len = ngx_strlen(buf_temp);
			return NGX_ERROR;
		}
		pos_network_addr_list = ctx->network_list;
		for (;
			pos_network_addr_list != NULL;
			pos_network_addr_list = pos_network_addr_list->next)
		{
			network_addr_data = pos_network_addr_list->data;
			if (network_addr_data == NULL)
				continue;

			if (network_addr_data->addr == cdir.u.in.addr
				&& network_addr_data->mask == cdir.u.in.mask
				&& pos_network_addr_list->delete == 0)
				break;
		}

		if (pos_network_addr_list == NULL)
		{
			snprintf(buf_temp, 256, "Do't find the item %s", value->data);
			reason->data = buf_temp;
			reason->len = ngx_strlen(buf_temp);
			return NGX_ERROR;
		}

		if (ngx_white_black_delete_from_file(value, zone_name) == NGX_ERROR)
		{
			pos_network_addr_list->delete = 0;
			snprintf(buf_temp, 256, "ngx_white_black_delete_from_file failed! the ip=%s  the zone_name=%s.", value->data, zone_name->data);
			reason->data = buf_temp;
			reason->len = ngx_strlen(buf_temp);
			return NGX_ERROR;
		}
		
		pos_network_addr_list->delete = 1;		
		return NGX_OK;
	}
	
	node = ngx_white_black_list_lookup(ctx->rbtree, value, hash);
	if (node == NULL)
	{
		snprintf(buf_temp, 256, "Do't find the item %s", value->data);
		reason->data = buf_temp;
		reason->len = ngx_strlen(buf_temp);
		return NGX_ERROR;
	}

	if (ngx_white_black_delete_from_file(value, zone_name) == NGX_ERROR)
	{
		snprintf(buf_temp, 256, "ngx_white_black_delete_from_file failed! the ip=%s  the zone_name=%s.", value->data, zone_name->data);
		reason->data = buf_temp;
		reason->len = ngx_strlen(buf_temp);
		return NGX_ERROR;
	}
	
	ngx_shmtx_lock(&shpool->mutex);
	ngx_rbtree_delete(ctx->rbtree, node);
	ngx_shmtx_unlock(&shpool->mutex);
	
	return NGX_OK;
}

