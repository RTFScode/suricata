/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Flow queue handler functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "flow-private.h"
#include "flow-queue.h"
#include "flow-util.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"

FlowQueue *FlowQueueNew()
{
    FlowQueue *q = (FlowQueue *)SCMalloc(sizeof(FlowQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in FlowQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = FlowQueueInit(q);
    return q;
}

FlowQueue *FlowQueueInit (FlowQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(FlowQueue));
        FQLOCK_INIT(q);
    }
    return q;
}

/**
 *  \brief Destroy a flow queue
 *
 *  \param q the flow queue to destroy
 */
void FlowQueueDestroy (FlowQueue *q)
{
    FQLOCK_DESTROY(q);
}

/**
 *  \brief add a flow to a queue
 *
 *  \param q queue
 *  \param f flow
 */
/*
*	预申请到的流和释放的流都放在空闲队列中
*/
void FlowEnqueue (FlowQueue *q, Flow *f)
{
#ifdef DEBUG
    BUG_ON(q == NULL || f == NULL);
#endif

    FQLOCK_LOCK(q);

    /* more flows in queue */
	/*
	*	queue是一个双向队列
	*	新的流来的时候采用头插的方式
	*/
    if (q->top != NULL) {
        f->lnext = q->top;
        q->top->lprev = f;
        q->top = f;
    /* only flow */
    } else {
        q->top = f;
        q->bot = f;
    }
    q->len++;	//记录队列的长度(空闲队列中flow的个数)
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    FQLOCK_UNLOCK(q);
}

/**
 *  \brief remove a flow from the queue
 *
 *  \param q queue
 *
 *  \retval f flow or NULL if empty list.
 */
/*
*	从空闲队列中获取一个flow
*	获取失败返回NULL
*	成功返回flow
*/
Flow *FlowDequeue (FlowQueue *q)
{
    FQLOCK_LOCK(q);

    Flow *f = q->bot;
    if (f == NULL) {
        FQLOCK_UNLOCK(q);
        return NULL;
    }

    /* more packets in queue */
	//从双向队列的尾部拿一个flow
    if (q->bot->lprev != NULL) {
        q->bot = q->bot->lprev;
        q->bot->lnext = NULL;
    /* just the one we remove, so now empty */
    } else {//空闲队列中只有一个节点
        q->top = NULL;
        q->bot = NULL;
    }

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;

    f->lnext = NULL;
    f->lprev = NULL;

    FQLOCK_UNLOCK(q);
    return f;
}

/**
 *  \brief Transfer a flow from a queue to the spare queue
 *
 *  \param f the flow to be transfered
 *  \param q the source queue, where the flow will be removed. This queue is locked.
 *
 *  \note spare queue needs locking
 */
void FlowMoveToSpare(Flow *f)
{
    /* now put it in spare */
    FQLOCK_LOCK(&flow_spare_q);

    /* add to new queue (append) */
    f->lprev = flow_spare_q.bot;
    if (f->lprev != NULL)
        f->lprev->lnext = f;
    f->lnext = NULL;
    flow_spare_q.bot = f;
    if (flow_spare_q.top == NULL)
        flow_spare_q.top = f;

    flow_spare_q.len++;
#ifdef DBG_PERF
    if (flow_spare_q.len > flow_spare_q.dbg_maxlen)
        flow_spare_q.dbg_maxlen = flow_spare_q.len;
#endif /* DBG_PERF */

    FQLOCK_UNLOCK(&flow_spare_q);
}

