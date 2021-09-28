/* Structure dynamic extension infrastructure
 * Copyright (C) 2004 Rusty Russell IBM Corporation
 * Copyright (C) 2007 Netfilter Core Team <coreteam@netfilter.org>
 * Copyright (C) 2007 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_extend.h>

/*conntrack extensions要用到的结构，extensions一共有4个type，其中helper类型的数据还需要一个额外的hash表，即nf_ct_helper_hash。*/
static struct nf_ct_ext_type __rcu *nf_ct_ext_types[NF_CT_EXT_NUM];
static DEFINE_MUTEX(nf_ct_ext_type_mutex);
#define NF_CT_EXT_PREALLOC	128u /* conntrack events are on by default */



/*******************************************************************************
 函数名称 :  nf_ct_ext_destroy
 功能描述 :  期望链接解除关联
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
void nf_ct_ext_destroy(struct nf_conn *ct)
{
	unsigned int i;
	struct nf_ct_ext_type *t;

	/**/
	for (i = 0; i < NF_CT_EXT_NUM; i++) 
	{
		rcu_read_lock();
		t = rcu_dereference(nf_ct_ext_types[i]);

		/* Here the nf_ct_ext_type might have been unregisterd.
		 * I.e., it has responsible to cleanup private
		 * area in all conntracks when it is unregisterd.
		 */

		/*资源destroy*/
		if (t && t->destroy)
			t->destroy(ct);
		
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_ext_destroy);


/*******************************************************************************
 函数名称 :  nf_ct_ext_add
 功能描述 :  给一个nf_conn->ext赋值，根据id给ct->ext分配一个新的ext数据，新数据清0。 
 输入参数 :  ct---链接跟踪
 			 id---extension数据的类型，即上面4个其中的一种
 输出参数 :  无
 返回值　 :  新添加的ext数据指针，data中新分配空间的位置。
 			 返回void *类型，根据参数id可以转换成struct nf_conn_help、struct nf_conn_nat、struct nf_conn_counter
 			 或structnf_conntrack_ecache其中的一种类型
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
void *nf_ct_ext_add(struct nf_conn *ct, enum nf_ct_ext_id id, gfp_t gfp)
{
	unsigned int newlen, newoff, oldlen, alloc;

	/*连接跟踪的扩展*/
	struct nf_ct_ext *old, *new;

	/*连接跟踪的扩展类型*/
	struct nf_ct_ext_type *t;

	/* Conntrack must not be confirmed to avoid races on reallocation. */
	WARN_ON(nf_ct_is_confirmed(ct));

	/*helper扩展功能*/
	old = ct->ext;
	/* 如果连ct->ext都还没有，说明肯定没有ext数据。所以先分配一个ct->ext，然后分配类型为id的ext数据，数据位置由ct->ext->offset[id]指向。*/
	if (old) 
	{
		/* --- ct->ext不为NULL，说明不是第一次分配了 --- */
	
		/* 如果类型为id的数据已经存在，直接返回。 */
		if (__nf_ct_ext_exist(old, id))
			return NULL;
		
		oldlen = old->len;
	} 
	else
	{
		oldlen = sizeof(*new);
	}

	rcu_read_lock();

	/*tftp对应的结构nf_ct_ext_type*/
	t = rcu_dereference(nf_ct_ext_types[id]);
	if (!t) {
		rcu_read_unlock();
		return NULL;
	}
	
	/* 找到已有数据的尾端，从这里开始分配新的id的数据。 */
	newoff = ALIGN(oldlen, t->align);
	newlen = newoff + t->len;
	rcu_read_unlock();

	alloc = max(newlen, NF_CT_EXT_PREALLOC);
	kmemleak_not_leak(old);
	new = __krealloc(old, alloc, gfp);

	/* 由于上面是realloc，可能起始地址改变了，如果变了地址，就先把原有数据考过去。 */
	if (!new)
		return NULL;

	/*helper扩展功能不存在*/
	if (!old) 
	{
		memset(new->offset, 0, sizeof(new->offset));
		ct->ext = new;
	}
	else if (new != old) 
	{
		kfree_rcu(old, rcu);
		rcu_assign_pointer(ct->ext, new);
	}

	/* 调整ct->ext的offset[id]和len */
	new->offset[id] = newoff;
	new->len = newlen;

	/* 清0*/
	memset((void *)new + newoff, 0, newlen - newoff);
	return (void *)new + newoff;
}
EXPORT_SYMBOL(nf_ct_ext_add);

/* This MUST be called in process context. */
/*******************************************************************************
 函数名称 :  nf_ct_extend_register
 功能描述 :  
 输入参数 :  
 输出参数 :  无
 返回值　 :  无
 --------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者 :  
 修改目的 :  
 修改日期 :  
*******************************************************************************/
int nf_ct_extend_register(const struct nf_ct_ext_type *type)
{
	int ret = 0;

	mutex_lock(&nf_ct_ext_type_mutex);
	if (nf_ct_ext_types[type->id]) 
	{
		ret = -EBUSY;
		goto out;
	}

	rcu_assign_pointer(nf_ct_ext_types[type->id], type);
out:
	mutex_unlock(&nf_ct_ext_type_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_extend_register);

/* This MUST be called in process context. */
void nf_ct_extend_unregister(const struct nf_ct_ext_type *type)
{
	mutex_lock(&nf_ct_ext_type_mutex);
	RCU_INIT_POINTER(nf_ct_ext_types[type->id], NULL);
	mutex_unlock(&nf_ct_ext_type_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_ct_extend_unregister);
