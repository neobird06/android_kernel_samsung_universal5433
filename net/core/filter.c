/*
 * Linux Socket Filter - Kernel level socket filtering
 *
 * Author:
 *     Jay Schulist <jschlst@samba.org>
 *
 * Based on the design of:
 *     - The Berkeley Packet Filter
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Andi Kleen - Fix a few bad bugs and races.
 * Kris Katterjohn - Added many additional checks in sk_chk_filter()
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/sock_diag.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/gfp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <asm/unaligned.h>
#include <linux/filter.h>
#include <linux/reciprocal_div.h>
#include <linux/ratelimit.h>
#include <linux/seccomp.h>
#include <linux/if_vlan.h>

/* No hurry in this branch
 *
 * Exported for the bpf jit load helper.
 */
void *bpf_internal_load_pointer_neg_helper(const struct sk_buff *skb, int k, unsigned int size)
{
	u8 *ptr = NULL;

	if (k >= SKF_NET_OFF)
		ptr = skb_network_header(skb) + k - SKF_NET_OFF;
	else if (k >= SKF_LL_OFF)
		ptr = skb_mac_header(skb) + k - SKF_LL_OFF;

	if (ptr >= skb->head && ptr + size <= skb_tail_pointer(skb))
		return ptr;
	return NULL;
}

static inline void *load_pointer(const struct sk_buff *skb, int k,
				 unsigned int size, void *buffer)
{
	if (k >= 0)
		return skb_header_pointer(skb, k, size, buffer);
	return bpf_internal_load_pointer_neg_helper(skb, k, size);
}

/**
 *	sk_filter - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *
 * Run the filter code and then cut skb->data to correct size returned by
 * sk_run_filter. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to sk_run_filter. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */
int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	int err;
	struct sk_filter *filter;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC))
		return -ENOMEM;
	err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
	if (err)
		return err;

	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		unsigned int pkt_len = SK_RUN_FILTER(filter, skb);

		err = pkt_len ? pskb_trim(skb, pkt_len) : -EPERM;
		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
EXPORT_SYMBOL(sk_filter);

/**
 *	sk_run_filter - run a filter on a socket
 *	@skb: buffer to run the filter on
 *	@fentry: filter to apply
 *
 * Decode and apply filter instructions to the skb->data.
 * Return length to keep, 0 for none. @skb is the data we are
 * filtering, @filter is the array of filter instructions.
 * Because all jumps are guaranteed to be before last instruction,
 * and last instruction guaranteed to be a RET, we dont need to check
 * flen. (We used to pass to this function the length of filter)
 */
unsigned int sk_run_filter(const struct sk_buff *skb,
			   const struct sock_filter *fentry)
{
	void *ptr;
	u32 A = 0;			/* Accumulator */
	u32 X = 0;			/* Index Register */
	u32 mem[BPF_MEMWORDS];		/* Scratch Memory Store */
	u32 tmp;
	int k;

	/*
	 * Process array of filter instructions.
	 */
	for (;; fentry++) {
#if defined(CONFIG_X86_32)
#define	K (fentry->k)
#else
		const u32 K = fentry->k;
#endif

		switch (fentry->code) {
		case BPF_S_ALU_ADD_X:
			A += X;
			continue;
		case BPF_S_ALU_ADD_K:
			A += K;
			continue;
		case BPF_S_ALU_SUB_X:
			A -= X;
			continue;
		case BPF_S_ALU_SUB_K:
			A -= K;
			continue;
		case BPF_S_ALU_MUL_X:
			A *= X;
			continue;
		case BPF_S_ALU_MUL_K:
			A *= K;
			continue;
		case BPF_S_ALU_DIV_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
		case BPF_S_ALU_DIV_K:
			A = reciprocal_divide(A, K);
			continue;
		case BPF_S_ALU_MOD_X:
			if (X == 0)
				return 0;
			A %= X;
			continue;
		case BPF_S_ALU_MOD_K:
			A %= K;
			continue;
		case BPF_S_ALU_AND_X:
			A &= X;
			continue;
		case BPF_S_ALU_AND_K:
			A &= K;
			continue;
		case BPF_S_ALU_OR_X:
			A |= X;
			continue;
		case BPF_S_ALU_OR_K:
			A |= K;
			continue;
		case BPF_S_ANC_ALU_XOR_X:
		case BPF_S_ALU_XOR_X:
			A ^= X;
			continue;
		case BPF_S_ALU_XOR_K:
			A ^= K;
			continue;
		case BPF_S_ALU_LSH_X:
			A <<= X;
			continue;
		case BPF_S_ALU_LSH_K:
			A <<= K;
			continue;
		case BPF_S_ALU_RSH_X:
			A >>= X;
			continue;
		case BPF_S_ALU_RSH_K:
			A >>= K;
			continue;
		case BPF_S_ALU_NEG:
			A = -A;
			continue;
		case BPF_S_JMP_JA:
			fentry += K;
			continue;
		case BPF_S_JMP_JGT_K:
			fentry += (A > K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_K:
			fentry += (A >= K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_K:
			fentry += (A == K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_K:
			fentry += (A & K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGT_X:
			fentry += (A > X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_X:
			fentry += (A >= X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_X:
			fentry += (A == X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_X:
			fentry += (A & X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_LD_W_ABS:
			k = K;
load_w:
			ptr = load_pointer(skb, k, 4, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be32(ptr);
				continue;
	if (len <= 0 || len > BPF_MAXINSNS)
		return -EINVAL;

	if (new_prog) {
		addrs = kcalloc(len, sizeof(*addrs),
				GFP_KERNEL | __GFP_NOWARN);
		if (!addrs)
			return -ENOMEM;
	}

do_pass:
	new_insn = new_prog;
	fp = prog;

	/* Classic BPF related prologue emission. */
	if (new_insn) {
		/* Classic BPF expects A and X to be reset first. These need
		 * to be guaranteed to be the first two instructions.
		 */
		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_X, BPF_REG_X);

		/* All programs must keep CTX in callee saved BPF_REG_CTX.
		 * In eBPF case it's done by the compiler, here we need to
		 * do this ourself. Initial CTX is present in BPF_REG_ARG1.
		 */
		*new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
	} else {
		new_insn += 3;
	}

	for (i = 0; i < len; fp++, i++) {
		struct bpf_insn tmp_insns[6] = { };
		struct bpf_insn *insn = tmp_insns;

		if (addrs)
			addrs[i] = new_insn - new_prog;

		switch (fp->code) {
		/* All arithmetic insns and skb loads map as-is. */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_IND | BPF_W:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_B:
			/* Check for overloaded BPF extension and
			 * directly convert it if found, otherwise
			 * just move on with mapping.
			 */
			if (BPF_CLASS(fp->code) == BPF_LD &&
			    BPF_MODE(fp->code) == BPF_ABS &&
			    convert_bpf_extensions(fp, &insn))
				break;

			if (fp->code == (BPF_ALU | BPF_DIV | BPF_X) ||
			    fp->code == (BPF_ALU | BPF_MOD | BPF_X))
				*insn++ = BPF_MOV32_REG(BPF_REG_X, BPF_REG_X);

			*insn = BPF_RAW_INSN(fp->code, BPF_REG_A, BPF_REG_X, 0, fp->k);
			break;

		/* Jump transformation cannot use BPF block macros
		 * everywhere as offset calculation and target updates
		 * require a bit more work than the rest, i.e. jump
		 * opcodes map as-is, but offsets need adjustment.
		 */

#define BPF_EMIT_JMP							\
	do {								\
		if (target >= len || target < 0)			\
			goto err;					\
		insn->off = addrs ? addrs[target] - addrs[i] - 1 : 0;	\
		/* Adjust pc relative offset for 2nd or 3rd insn. */	\
		insn->off -= insn - tmp_insns;				\
	} while (0)

		case BPF_JMP | BPF_JA:
			target = i + fp->k + 1;
			insn->code = fp->code;
			BPF_EMIT_JMP;
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
			if (BPF_SRC(fp->code) == BPF_K && (int) fp->k < 0) {
				/* BPF immediates are signed, zero extend
				 * immediate into tmp register and use it
				 * in compare insn.
				 */
				*insn++ = BPF_MOV32_IMM(BPF_REG_TMP, fp->k);

				insn->dst_reg = BPF_REG_A;
				insn->src_reg = BPF_REG_TMP;
				bpf_src = BPF_X;
			} else {
				insn->dst_reg = BPF_REG_A;
				insn->imm = fp->k;
				bpf_src = BPF_SRC(fp->code);
				insn->src_reg = bpf_src == BPF_X ? BPF_REG_X : 0;
			}
			return 0;
		case BPF_S_LD_H_ABS:
			k = K;
load_h:
			ptr = load_pointer(skb, k, 2, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be16(ptr);
				continue;
			}
			return 0;
		case BPF_S_LD_B_ABS:
			k = K;
load_b:
			ptr = load_pointer(skb, k, 1, &tmp);
			if (ptr != NULL) {
				A = *(u8 *)ptr;
				continue;
			}
			return 0;
		case BPF_S_LD_W_LEN:
			A = skb->len;
			continue;
		case BPF_S_LDX_W_LEN:
			X = skb->len;
			continue;
		case BPF_S_LD_W_IND:
			k = X + K;
			goto load_w;
		case BPF_S_LD_H_IND:
			k = X + K;
			goto load_h;
		case BPF_S_LD_B_IND:
			k = X + K;
			goto load_b;
		case BPF_S_LDX_B_MSH:
			ptr = load_pointer(skb, K, 1, &tmp);
			if (ptr != NULL) {
				X = (*(u8 *)ptr & 0xf) << 2;
				continue;
			}
			return 0;
		case BPF_S_LD_IMM:
			A = K;
			continue;
		case BPF_S_LDX_IMM:
			X = K;
			continue;
		case BPF_S_LD_MEM:
			A = mem[K];
			continue;
		case BPF_S_LDX_MEM:
			X = mem[K];
			continue;
		case BPF_S_MISC_TAX:
			X = A;
			continue;
		case BPF_S_MISC_TXA:
			A = X;
			continue;
		case BPF_S_RET_K:
			return K;
		case BPF_S_RET_A:
			return A;
		case BPF_S_ST:
			mem[K] = A;
			continue;
		case BPF_S_STX:
			mem[K] = X;
			continue;
		case BPF_S_ANC_PROTOCOL:
			A = ntohs(skb->protocol);
			continue;
		case BPF_S_ANC_PKTTYPE:
			A = skb->pkt_type;
			continue;
		case BPF_S_ANC_IFINDEX:
			if (!skb->dev)
				return 0;
			A = skb->dev->ifindex;
			continue;
		case BPF_S_ANC_MARK:
			A = skb->mark;
			continue;
		case BPF_S_ANC_QUEUE:
			A = skb->queue_mapping;
			continue;
		case BPF_S_ANC_HATYPE:
			if (!skb->dev)
				return 0;
			A = skb->dev->type;
			continue;
		case BPF_S_ANC_RXHASH:
			A = skb->rxhash;
			continue;
		case BPF_S_ANC_CPU:
			A = raw_smp_processor_id();
			continue;
		case BPF_S_ANC_VLAN_TAG:
			A = vlan_tx_tag_get(skb);
			continue;
		case BPF_S_ANC_VLAN_TAG_PRESENT:
			A = !!vlan_tx_tag_present(skb);
			continue;
		case BPF_S_ANC_PAY_OFFSET:
			A = __skb_get_poff(skb);
			continue;
		case BPF_S_ANC_NLATTR: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = nla_find((struct nlattr *)&skb->data[A],
				       skb->len - A, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
		case BPF_S_ANC_NLATTR_NEST: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = (struct nlattr *)&skb->data[A];
			if (nla->nla_len > A - skb->len)
				return 0;

			nla = nla_find_nested(nla, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
#ifdef CONFIG_SECCOMP_FILTER
		case BPF_S_ANC_SECCOMP_LD_W:
			A = seccomp_bpf_load(fentry->k);
			continue;
#endif
		default:
			WARN_RATELIMIT(1, "Unknown code:%u jt:%u tf:%u k:%u\n",
				       fentry->code, fentry->jt,
				       fentry->jf, fentry->k);
			return 0;
		}
	}

	return 0;
}
EXPORT_SYMBOL(sk_run_filter);

/*
 * Security :
 * A BPF program is able to use 16 cells of memory to store intermediate
 * values (check u32 mem[BPF_MEMWORDS] in sk_run_filter())
 * As we dont want to clear mem[] array for each packet going through
 * sk_run_filter(), we check that filter loaded by user never try to read
 * a cell if not previously written, and we check all branches to be sure
 * a malicious user doesn't try to abuse us.
 */
static int check_load_and_stores(struct sock_filter *filter, int flen)
{
	u16 *masks, memvalid = 0; /* one bit per cell, 16 cells */
	int pc, ret = 0;

	BUILD_BUG_ON(BPF_MEMWORDS > 16);
	masks = kmalloc(flen * sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return -ENOMEM;
	memset(masks, 0xff, flen * sizeof(*masks));

	for (pc = 0; pc < flen; pc++) {
		memvalid &= masks[pc];

		switch (filter[pc].code) {
		case BPF_S_ST:
		case BPF_S_STX:
			memvalid |= (1 << filter[pc].k);
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
			if (!(memvalid & (1 << filter[pc].k))) {
				ret = -EINVAL;
				goto error;
			}
			break;
		case BPF_S_JMP_JA:
			/* a jump must set masks on target */
			masks[pc + 1 + filter[pc].k] &= memvalid;
			memvalid = ~0;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* a jump must set masks on targets */
			masks[pc + 1 + filter[pc].jt] &= memvalid;
			masks[pc + 1 + filter[pc].jf] &= memvalid;
			memvalid = ~0;
			break;
		}
	}
error:
	kfree(masks);
	return ret;
}

/**
 *	sk_chk_filter - verify socket filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Check the user's filter code. If we let some ugly
 * filter code slip through kaboom! The filter must contain
 * no references or jumps that are out of range, no illegal
 * instructions, and must end with a RET instruction.
 *
 * All jumps are forward as they are not signed.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
int sk_chk_filter(struct sock_filter *filter, unsigned int flen)
{
	/*
	 * Valid instructions are initialized to non-0.
	 * Invalid instructions are initialized to 0.
	 */
	static const u8 codes[] = {
		[BPF_ALU|BPF_ADD|BPF_K]  = BPF_S_ALU_ADD_K,
		[BPF_ALU|BPF_ADD|BPF_X]  = BPF_S_ALU_ADD_X,
		[BPF_ALU|BPF_SUB|BPF_K]  = BPF_S_ALU_SUB_K,
		[BPF_ALU|BPF_SUB|BPF_X]  = BPF_S_ALU_SUB_X,
		[BPF_ALU|BPF_MUL|BPF_K]  = BPF_S_ALU_MUL_K,
		[BPF_ALU|BPF_MUL|BPF_X]  = BPF_S_ALU_MUL_X,
		[BPF_ALU|BPF_DIV|BPF_X]  = BPF_S_ALU_DIV_X,
		[BPF_ALU|BPF_MOD|BPF_K]  = BPF_S_ALU_MOD_K,
		[BPF_ALU|BPF_MOD|BPF_X]  = BPF_S_ALU_MOD_X,
		[BPF_ALU|BPF_AND|BPF_K]  = BPF_S_ALU_AND_K,
		[BPF_ALU|BPF_AND|BPF_X]  = BPF_S_ALU_AND_X,
		[BPF_ALU|BPF_OR|BPF_K]   = BPF_S_ALU_OR_K,
		[BPF_ALU|BPF_OR|BPF_X]   = BPF_S_ALU_OR_X,
		[BPF_ALU|BPF_XOR|BPF_K]  = BPF_S_ALU_XOR_K,
		[BPF_ALU|BPF_XOR|BPF_X]  = BPF_S_ALU_XOR_X,
		[BPF_ALU|BPF_LSH|BPF_K]  = BPF_S_ALU_LSH_K,
		[BPF_ALU|BPF_LSH|BPF_X]  = BPF_S_ALU_LSH_X,
		[BPF_ALU|BPF_RSH|BPF_K]  = BPF_S_ALU_RSH_K,
		[BPF_ALU|BPF_RSH|BPF_X]  = BPF_S_ALU_RSH_X,
		[BPF_ALU|BPF_NEG]        = BPF_S_ALU_NEG,
		[BPF_LD|BPF_W|BPF_ABS]   = BPF_S_LD_W_ABS,
		[BPF_LD|BPF_H|BPF_ABS]   = BPF_S_LD_H_ABS,
		[BPF_LD|BPF_B|BPF_ABS]   = BPF_S_LD_B_ABS,
		[BPF_LD|BPF_W|BPF_LEN]   = BPF_S_LD_W_LEN,
		[BPF_LD|BPF_W|BPF_IND]   = BPF_S_LD_W_IND,
		[BPF_LD|BPF_H|BPF_IND]   = BPF_S_LD_H_IND,
		[BPF_LD|BPF_B|BPF_IND]   = BPF_S_LD_B_IND,
		[BPF_LD|BPF_IMM]         = BPF_S_LD_IMM,
		[BPF_LDX|BPF_W|BPF_LEN]  = BPF_S_LDX_W_LEN,
		[BPF_LDX|BPF_B|BPF_MSH]  = BPF_S_LDX_B_MSH,
		[BPF_LDX|BPF_IMM]        = BPF_S_LDX_IMM,
		[BPF_MISC|BPF_TAX]       = BPF_S_MISC_TAX,
		[BPF_MISC|BPF_TXA]       = BPF_S_MISC_TXA,
		[BPF_RET|BPF_K]          = BPF_S_RET_K,
		[BPF_RET|BPF_A]          = BPF_S_RET_A,
		[BPF_ALU|BPF_DIV|BPF_K]  = BPF_S_ALU_DIV_K,
		[BPF_LD|BPF_MEM]         = BPF_S_LD_MEM,
		[BPF_LDX|BPF_MEM]        = BPF_S_LDX_MEM,
		[BPF_ST]                 = BPF_S_ST,
		[BPF_STX]                = BPF_S_STX,
		[BPF_JMP|BPF_JA]         = BPF_S_JMP_JA,
		[BPF_JMP|BPF_JEQ|BPF_K]  = BPF_S_JMP_JEQ_K,
		[BPF_JMP|BPF_JEQ|BPF_X]  = BPF_S_JMP_JEQ_X,
		[BPF_JMP|BPF_JGE|BPF_K]  = BPF_S_JMP_JGE_K,
		[BPF_JMP|BPF_JGE|BPF_X]  = BPF_S_JMP_JGE_X,
		[BPF_JMP|BPF_JGT|BPF_K]  = BPF_S_JMP_JGT_K,
		[BPF_JMP|BPF_JGT|BPF_X]  = BPF_S_JMP_JGT_X,
		[BPF_JMP|BPF_JSET|BPF_K] = BPF_S_JMP_JSET_K,
		[BPF_JMP|BPF_JSET|BPF_X] = BPF_S_JMP_JSET_X,
	};
	int pc;
	bool anc_found;

	if (flen == 0 || flen > BPF_MAXINSNS)
		return -EINVAL;

	/* check the filter code now */
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;

		if (code >= ARRAY_SIZE(codes))
			return -EINVAL;
		code = codes[code];
		if (!code)
			return -EINVAL;
		/* Some instructions need special checks */
		switch (code) {
		case BPF_S_ALU_DIV_K:
			/* check for division by zero */
			if (ftest->k == 0)
				return -EINVAL;
			ftest->k = reciprocal_value(ftest->k);
			break;
		case BPF_S_ALU_MOD_K:
			/* check for division by zero */
			if (ftest->k == 0)
				return -EINVAL;
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
			/* check for invalid memory addresses */
			if (ftest->k >= BPF_MEMWORDS)
				return -EINVAL;
			break;
		case BPF_S_JMP_JA:
			/*
			 * Note, the large ftest->k might cause loops.
			 * Compare this with conditional jumps below,
			 * where offsets are limited. --ANK (981016)
			 */
			if (ftest->k >= (unsigned int)(flen-pc-1))
				return -EINVAL;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* for conditionals both must be safe */
			if (pc + ftest->jt + 1 >= flen ||
			    pc + ftest->jf + 1 >= flen)
				return -EINVAL;
			break;
		case BPF_S_LD_W_ABS:
		case BPF_S_LD_H_ABS:
		case BPF_S_LD_B_ABS:
			anc_found = false;
#define ANCILLARY(CODE) case SKF_AD_OFF + SKF_AD_##CODE:	\
				code = BPF_S_ANC_##CODE;	\
				anc_found = true;		\
				break
			switch (ftest->k) {
			ANCILLARY(PROTOCOL);
			ANCILLARY(PKTTYPE);
			ANCILLARY(IFINDEX);
			ANCILLARY(NLATTR);
			ANCILLARY(NLATTR_NEST);
			ANCILLARY(MARK);
			ANCILLARY(QUEUE);
			ANCILLARY(HATYPE);
			ANCILLARY(RXHASH);
			ANCILLARY(CPU);
			ANCILLARY(ALU_XOR_X);
			ANCILLARY(VLAN_TAG);
			ANCILLARY(VLAN_TAG_PRESENT);
			ANCILLARY(PAY_OFFSET);
			}

			/* ancillary operation unknown or unsupported */
			if (anc_found == false && ftest->k >= SKF_AD_OFF)
				return -EINVAL;
		}
		ftest->code = code;
	}

	/* last instruction must be a RET code */
	switch (filter[flen - 1].code) {
	case BPF_S_RET_K:
	case BPF_S_RET_A:
		return check_load_and_stores(filter, flen);
	}
	return -EINVAL;
}
EXPORT_SYMBOL(sk_chk_filter);

/**
 * 	sk_filter_release_rcu - Release a socket filter by rcu_head
 *	@rcu: rcu_head that contains the sk_filter to free
 */
void sk_filter_release_rcu(struct rcu_head *rcu)
{
	struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);

	bpf_jit_free(fp);
	kfree(fp);
}
EXPORT_SYMBOL(sk_filter_release_rcu);

static int __sk_prepare_filter(struct sk_filter *fp)
/**
 *	sk_filter_release - release a socket filter
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */
static void sk_filter_release(struct sk_filter *fp)
{
	if (atomic_dec_and_test(&fp->refcnt))
		call_rcu(&fp->rcu, sk_filter_release_rcu);
}

void sk_filter_uncharge(struct sock *sk, struct sk_filter *fp)
{
	u32 filter_size = bpf_prog_size(fp->prog->len);

	atomic_sub(filter_size, &sk->sk_omem_alloc);
	sk_filter_release(fp);
}

/* try to charge the socket memory if there is space available
 * return true on success
 */
bool sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	u32 filter_size = bpf_prog_size(fp->prog->len);

	/* same check as in sock_kmalloc() */
	if (filter_size <= sysctl_optmem_max &&
	    atomic_read(&sk->sk_omem_alloc) + filter_size < sysctl_optmem_max) {
		atomic_inc(&fp->refcnt);
		atomic_add(filter_size, &sk->sk_omem_alloc);
		return true;
	}
	return false;
}

static struct bpf_prog *bpf_migrate_filter(struct bpf_prog *fp)
{
	struct sock_filter *old_prog;
	struct bpf_prog *old_fp;
	int err, new_len, old_len = fp->len;

	/* We are free to overwrite insns et al right here as it
	 * won't be used at this point in time anymore internally
	 * after the migration to the internal BPF instruction
	 * representation.
	 */
	BUILD_BUG_ON(sizeof(struct sock_filter) !=
		     sizeof(struct bpf_insn));

	/* Conversion cannot happen on overlapping memory areas,
	 * so we need to keep the user BPF around until the 2nd
	 * pass. At this time, the user BPF is stored in fp->insns.
	 */
	old_prog = kmemdup(fp->insns, old_len * sizeof(struct sock_filter),
			   GFP_KERNEL | __GFP_NOWARN);
	if (!old_prog) {
		err = -ENOMEM;
		goto out_err;
	}

	/* 1st pass: calculate the new program length. */
	err = bpf_convert_filter(old_prog, old_len, NULL, &new_len);
	if (err)
		goto out_err_free;

	/* Expand fp for appending the new filter representation. */
	old_fp = fp;
	fp = bpf_prog_realloc(old_fp, bpf_prog_size(new_len), 0);
	if (!fp) {
		/* The old_fp is still around in case we couldn't
		 * allocate new memory, so uncharge on that one.
		 */
		fp = old_fp;
		err = -ENOMEM;
		goto out_err_free;
	}

	fp->len = new_len;

	/* 2nd pass: remap sock_filter insns into bpf_insn insns. */
	err = bpf_convert_filter(old_prog, old_len, fp->insnsi, &new_len);
	if (err)
		/* 2nd bpf_convert_filter() can fail only if it fails
		 * to allocate memory, remapping must succeed. Note,
		 * that at this time old_fp has already been released
		 * by krealloc().
		 */
		goto out_err_free;

	fp = bpf_prog_select_runtime(fp, &err);
	if (err)
		goto out_err_free;

	kfree(old_prog);
	return fp;

out_err_free:
	kfree(old_prog);
out_err:
	__bpf_prog_release(fp);
	return ERR_PTR(err);
}

static struct bpf_prog *bpf_prepare_filter(struct bpf_prog *fp,
					   bpf_aux_classic_check_t trans)
{
	int err;

	fp->bpf_func = sk_run_filter;

	err = sk_chk_filter(fp->insns, fp->len);
	if (err)
		return err;

	bpf_jit_compile(fp);
	return 0;
}

/**
 *	sk_unattached_filter_create - create an unattached filter
 *	@fprog: the filter program
 *	@pfp: the unattached filter that is created
 *
 * Create a filter independent of any socket. We first run some
 * sanity checks on it to make sure it does not explode on us later.
 * If an error occurs or there is insufficient memory for the filter
 * a negative errno code is returned. On success the return is zero.
 */
int sk_unattached_filter_create(struct sk_filter **pfp,
				struct sock_fprog *fprog)
{
	struct sk_filter *fp;
	unsigned int fsize = sizeof(struct sock_filter) * fprog->len;
	int err;

	/* Make sure new filter is there and in the right amounts. */
	if (fprog->filter == NULL)
		return -EINVAL;

	fp = kmalloc(fsize + sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;
	memcpy(fp->insns, fprog->filter, fsize);

	atomic_set(&fp->refcnt, 1);
	fp->len = fprog->len;

	err = __sk_prepare_filter(fp);
	if (err)
		goto free_mem;

	*pfp = fp;
	return 0;
free_mem:
	kfree(fp);
	return err;
}
EXPORT_SYMBOL_GPL(sk_unattached_filter_create);

void sk_unattached_filter_destroy(struct sk_filter *fp)
{
	sk_filter_release(fp);
}
EXPORT_SYMBOL_GPL(sk_unattached_filter_destroy);

/**
 *	sk_attach_filter - attach a socket filter
 *	@fprog: the filter program
 *	@sk: the socket to use
 *
 * Attach the user's filter code. We first run some sanity checks on
 * it to make sure it does not explode on us later. If an error
 * occurs or there is insufficient memory for the filter a negative
 * errno code is returned. On success the return is zero.
 */
int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
{
	struct sk_filter *fp, *old_fp;
	unsigned int fsize = sizeof(struct sock_filter) * fprog->len;
	int err;

	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return -EPERM;

	/* Make sure new filter is there and in the right amounts. */
	if (fprog->filter == NULL)
		return -EINVAL;

	fp = sock_kmalloc(sk, fsize+sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;
	if (copy_from_user(fp->insns, fprog->filter, fsize)) {
		sock_kfree_s(sk, fp, fsize+sizeof(*fp));
		return -EFAULT;
	}

	atomic_set(&fp->refcnt, 1);
	fp->len = fprog->len;

	err = __sk_prepare_filter(fp);
	if (err) {
		sk_filter_uncharge(sk, fp);
		return err;
	}

	old_fp = rcu_dereference_protected(sk->sk_filter,
					   sock_owned_by_user(sk));
	rcu_assign_pointer(sk->sk_filter, fp);

	if (old_fp)
		sk_filter_uncharge(sk, old_fp);
	return 0;
}
EXPORT_SYMBOL_GPL(sk_attach_filter);

int sk_attach_bpf(u32 ufd, struct sock *sk)
{
	struct bpf_prog *prog;
	int err;

	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return -EPERM;

	prog = bpf_prog_get_type(ufd, BPF_PROG_TYPE_SOCKET_FILTER);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	err = __sk_attach_prog(prog, sk);
	if (err < 0) {
		bpf_prog_put(prog);
		return err;
	}

	return 0;
}

struct bpf_scratchpad {
	union {
		__be32 diff[MAX_BPF_STACK / sizeof(__be32)];
		u8     buff[MAX_BPF_STACK];
	};
};

static DEFINE_PER_CPU(struct bpf_scratchpad, bpf_sp);

static inline int __bpf_try_make_writable(struct sk_buff *skb,
					  unsigned int write_len)
{
	return skb_ensure_writable(skb, write_len);
}

static inline int bpf_try_make_writable(struct sk_buff *skb,
					unsigned int write_len)
{
	int err = __bpf_try_make_writable(skb, write_len);

	bpf_compute_data_end(skb);
	return err;
}

static int bpf_try_make_head_writable(struct sk_buff *skb)
{
	return bpf_try_make_writable(skb, skb_headlen(skb));
}

static inline void bpf_push_mac_rcsum(struct sk_buff *skb)
{
	if (G_TC_AT(skb->tc_verd) & AT_INGRESS)
		skb_postpush_rcsum(skb, skb_mac_header(skb), skb->mac_len);
}

BPF_CALL_5(bpf_skb_store_bytes, struct sk_buff *, skb, u32, offset,
	   const void *, from, u32, len, u64, flags)
{
	void *ptr;

	if (unlikely(flags & ~(BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH)))
		return -EINVAL;
	if (unlikely(offset > 0xffff))
		return -EFAULT;
	if (unlikely(bpf_try_make_writable(skb, offset + len)))
		return -EFAULT;

	ptr = skb->data + offset;
	if (flags & BPF_F_RECOMPUTE_CSUM)
		__skb_postpull_rcsum(skb, ptr, len, offset);

	memcpy(ptr, from, len);

	if (flags & BPF_F_RECOMPUTE_CSUM)
		__skb_postpush_rcsum(skb, ptr, len, offset);
	if (flags & BPF_F_INVALIDATE_HASH){
		skb->rxhash = 0;
		skb->l4_rxhash = 0;
	}

	return 0;
}

static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
	.func		= bpf_skb_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_STACK,
	.arg4_type	= ARG_CONST_STACK_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_skb_load_bytes, const struct sk_buff *, skb, u32, offset,
	   void *, to, u32, len)
{
	void *ptr;

	if (unlikely(offset > 0xffff))
		goto err_clear;

	ptr = skb_header_pointer(skb, offset, len, to);
	if (unlikely(!ptr))
		goto err_clear;
	if (ptr != to)
		memcpy(to, ptr, len);

	return 0;
err_clear:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto bpf_skb_load_bytes_proto = {
	.func		= bpf_skb_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_RAW_STACK,
	.arg4_type	= ARG_CONST_STACK_SIZE,
};

BPF_CALL_2(bpf_skb_pull_data, struct sk_buff *, skb, u32, len)
{
	/* Idea is the following: should the needed direct read/write
	 * test fail during runtime, we can pull in more data and redo
	 * again, since implicitly, we invalidate previous checks here.
	 *
	 * Or, since we know how much we need to make read/writeable,
	 * this can be done once at the program beginning for direct
	 * access case. By this we overcome limitations of only current
	 * headroom being accessible.
	 */
	return bpf_try_make_writable(skb, len ? : skb_headlen(skb));
}

static const struct bpf_func_proto bpf_skb_pull_data_proto = {
	.func		= bpf_skb_pull_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_l3_csum_replace, struct sk_buff *, skb, u32, offset,
	   u64, from, u64, to, u64, flags)
{
	__sum16 *ptr;

	if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(offset > 0xffff || offset & 1))
		return -EFAULT;
	if (unlikely(bpf_try_make_writable(skb, offset + sizeof(*ptr))))
		return -EFAULT;

	ptr = (__sum16 *)(skb->data + offset);
	switch (flags & BPF_F_HDR_FIELD_MASK) {
	case 0:
		if (unlikely(from != 0))
			return -EINVAL;

		csum_replace_by_diff(ptr, to);
		break;
	case 2:
		csum_replace2(ptr, from, to);
		break;
	case 4:
		csum_replace4(ptr, from, to);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
	.func		= bpf_l3_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_l4_csum_replace, struct sk_buff *, skb, u32, offset,
	   u64, from, u64, to, u64, flags)
{
	bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__sum16 *ptr;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(offset > 0xffff || offset & 1))
		return -EFAULT;
	if (unlikely(bpf_try_make_writable(skb, offset + sizeof(*ptr))))
		return -EFAULT;

	ptr = (__sum16 *)(skb->data + offset);
	if (is_mmzero && !*ptr)
		return 0;

	switch (flags & BPF_F_HDR_FIELD_MASK) {
	case 0:
		if (unlikely(from != 0))
			return -EINVAL;

		inet_proto_csum_replace_by_diff(ptr, skb, to, is_pseudo);
		break;
	case 2:
		inet_proto_csum_replace2(ptr, skb, from, to, is_pseudo);
		break;
	case 4:
		inet_proto_csum_replace4(ptr, skb, from, to, is_pseudo);
		break;
	default:
		return -EINVAL;
	}

	if (is_mmzero && !*ptr)
		*ptr = CSUM_MANGLED_0;
	return 0;
}

static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
	.func		= bpf_l4_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_csum_diff, __be32 *, from, u32, from_size,
	   __be32 *, to, u32, to_size, __wsum, seed)
{
	struct bpf_scratchpad *sp = this_cpu_ptr(&bpf_sp);
	u32 diff_size = from_size + to_size;
	int i, j = 0;

	/* This is quite flexible, some examples:
	 *
	 * from_size == 0, to_size > 0,  seed := csum --> pushing data
	 * from_size > 0,  to_size == 0, seed := csum --> pulling data
	 * from_size > 0,  to_size > 0,  seed := 0    --> diffing data
	 *
	 * Even for diffing, from_size and to_size don't need to be equal.
	 */
	if (unlikely(((from_size | to_size) & (sizeof(__be32) - 1)) ||
		     diff_size > sizeof(sp->diff)))
		return -EINVAL;

	for (i = 0; i < from_size / sizeof(__be32); i++, j++)
		sp->diff[j] = ~from[i];
	for (i = 0; i <   to_size / sizeof(__be32); i++, j++)
		sp->diff[j] = to[i];

	return csum_partial(sp->diff, diff_size, seed);
}

static const struct bpf_func_proto bpf_csum_diff_proto = {
	.func		= bpf_csum_diff,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_STACK,
	.arg2_type	= ARG_CONST_STACK_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_STACK,
	.arg4_type	= ARG_CONST_STACK_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_csum_update, struct sk_buff *, skb, __wsum, csum)
{
	/* The interface is to be used in combination with bpf_csum_diff()
	 * for direct packet writes. csum rotation for alignment as well
	 * as emulating csum_sub() can be done from the eBPF program.
	 */
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		return (skb->csum = csum_add(skb->csum, csum));

	return -ENOTSUPP;
}

static const struct bpf_func_proto bpf_csum_update_proto = {
	.func		= bpf_csum_update,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static inline int __bpf_rx_skb(struct net_device *dev, struct sk_buff *skb)
{
	return dev_forward_skb(dev, skb);
}

static inline int __bpf_tx_skb(struct net_device *dev, struct sk_buff *skb)
{
	int ret;

	if (unlikely(__this_cpu_read(xmit_recursion) > XMIT_RECURSION_LIMIT)) {
		printk("bpf: recursion limit reached on datapath, buggy bpf program?\n");
		kfree_skb(skb);
		return -ENETDOWN;
	}

	skb->dev = dev;

	__this_cpu_inc(xmit_recursion);
	ret = dev_queue_xmit(skb);
	__this_cpu_dec(xmit_recursion);

	return ret;
}

BPF_CALL_3(bpf_clone_redirect, struct sk_buff *, skb, u32, ifindex, u64, flags)
{
	struct net_device *dev;
	struct sk_buff *clone;
	int ret;

	if (unlikely(flags & ~(BPF_F_INGRESS)))
		return -EINVAL;

	dev = dev_get_by_index_rcu(dev_net(skb->dev), ifindex);
	if (unlikely(!dev))
		return -EINVAL;

	clone = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(!clone))
		return -ENOMEM;

	/* For direct write, we need to keep the invariant that the skbs
	 * we're dealing with need to be uncloned. Should uncloning fail
	 * here, we need to free the just generated clone to unclone once
	 * again.
	 */
	ret = bpf_try_make_head_writable(skb);
	if (unlikely(ret)) {
		kfree_skb(clone);
		return -ENOMEM;
	}

	bpf_push_mac_rcsum(clone);

	return flags & BPF_F_INGRESS ?
	       __bpf_rx_skb(dev, clone) : __bpf_tx_skb(dev, clone);
}

static const struct bpf_func_proto bpf_clone_redirect_proto = {
	.func           = bpf_clone_redirect,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_ANYTHING,
};

struct redirect_info {
	u32 ifindex;
	u32 flags;
};

static DEFINE_PER_CPU(struct redirect_info, redirect_info);

BPF_CALL_2(bpf_redirect, u32, ifindex, u64, flags)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);

	if (unlikely(flags & ~(BPF_F_INGRESS)))
		return TC_ACT_SHOT;

	ri->ifindex = ifindex;
	ri->flags = flags;

	return TC_ACT_REDIRECT;
}

int skb_do_redirect(struct sk_buff *skb)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
	struct net_device *dev;

	dev = dev_get_by_index_rcu(dev_net(skb->dev), ri->ifindex);
	ri->ifindex = 0;
	if (unlikely(!dev)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	bpf_push_mac_rcsum(skb);

	return ri->flags & BPF_F_INGRESS ?
	       __bpf_rx_skb(dev, skb) : __bpf_tx_skb(dev, skb);
}

static const struct bpf_func_proto bpf_redirect_proto = {
	.func           = bpf_redirect,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_ANYTHING,
	.arg2_type      = ARG_ANYTHING,
};

BPF_CALL_1(bpf_get_cgroup_classid, const struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
	.func           = bpf_get_cgroup_classid,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_route_realm, const struct sk_buff *, skb)
{
	return dst_tclassid(skb);
}

static const struct bpf_func_proto bpf_get_route_realm_proto = {
	.func           = bpf_get_route_realm,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_hash_recalc, struct sk_buff *, skb)
{
	/* If skb_clear_hash() was called due to mangling, we can
	 * trigger SW recalculation here. Later access to hash
	 * can then use the inline skb->hash via context directly
	 * instead of calling this helper again.
	 */
	return skb_get_rxhash(skb);
}

static const struct bpf_func_proto bpf_get_hash_recalc_proto = {
	.func		= bpf_get_hash_recalc,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_set_hash_invalid, struct sk_buff *, skb)
{
	/* After all direct packet write, this can be used once for
	 * triggering a lazy recalc on next skb_get_hash() invocation.
	 */
	skb->rxhash = 0;
	skb->l4_rxhash = 0;
	return 0;
}

static const struct bpf_func_proto bpf_set_hash_invalid_proto = {
	.func		= bpf_set_hash_invalid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

static int bpf_skb_generic_push(struct sk_buff *skb, u32 off, u32 len)
{
	/* Caller already did skb_cow() with len as headroom,
	 * so no need to do it here.
	 */
	skb_push(skb, len);
	memmove(skb->data, skb->data + len, off);
	memset(skb->data + off, 0, len);

	/* No skb_postpush_rcsum(skb, skb->data + off, len)
	 * needed here as it does not change the skb->csum
	 * result for checksum complete when summing over
	 * zeroed blocks.
	 */
	return 0;
}

static int bpf_skb_generic_pop(struct sk_buff *skb, u32 off, u32 len)
{
	/* skb_ensure_writable() is not needed here, as we're
	 * already working on an uncloned skb.
	 */
	if (unlikely(!pskb_may_pull(skb, off + len)))
		return -ENOMEM;

	skb_postpull_rcsum(skb, skb->data + off, len);
	memmove(skb->data + len, skb->data, off);
	__skb_pull(skb, len);

	return 0;
}

static int bpf_skb_net_hdr_push(struct sk_buff *skb, u32 off, u32 len)
{
	bool trans_same = skb->transport_header == skb->network_header;
	int ret;

	/* There's no need for __skb_push()/__skb_pull() pair to
	 * get to the start of the mac header as we're guaranteed
	 * to always start from here under eBPF.
	 */
	ret = bpf_skb_generic_push(skb, off, len);
	if (likely(!ret)) {
		skb->mac_header -= len;
		skb->network_header -= len;
		if (trans_same)
			skb->transport_header = skb->network_header;
	}

	return ret;
}

static int bpf_skb_net_hdr_pop(struct sk_buff *skb, u32 off, u32 len)
{
	bool trans_same = skb->transport_header == skb->network_header;
	int ret;

	/* Same here, __skb_push()/__skb_pull() pair not needed. */
	ret = bpf_skb_generic_pop(skb, off, len);
	if (likely(!ret)) {
		skb->mac_header += len;
		skb->network_header += len;
		if (trans_same)
			skb->transport_header = skb->network_header;
	}

	return ret;
}

static int bpf_skb_proto_4_to_6(struct sk_buff *skb)
{
	const u32 len_diff = sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	u32 off = skb->network_header - skb->mac_header;
	int ret;

	ret = skb_cow(skb, len_diff);
	if (unlikely(ret < 0))
		return ret;

	ret = bpf_skb_net_hdr_push(skb, off, len_diff);
	if (unlikely(ret < 0))
		return ret;

	if (skb_is_gso(skb)) {
		/* SKB_GSO_UDP stays as is. SKB_GSO_TCPV4 needs to
		 * be changed into SKB_GSO_TCPV6.
		 */
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
			skb_shinfo(skb)->gso_type &= ~SKB_GSO_TCPV4;
			skb_shinfo(skb)->gso_type |=  SKB_GSO_TCPV6;
		}

		/* Header must be checked, and gso_segs recomputed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	skb->protocol = htons(ETH_P_IPV6);
	skb->rxhash = 0;
	skb->l4_rxhash = 0;

	return 0;
}

static int bpf_skb_proto_6_to_4(struct sk_buff *skb)
{
	const u32 len_diff = sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	u32 off = skb->network_header - skb->mac_header;
	int ret;

	ret = skb_unclone(skb, GFP_ATOMIC);
	if (unlikely(ret < 0))
		return ret;

	ret = bpf_skb_net_hdr_pop(skb, off, len_diff);
	if (unlikely(ret < 0))
		return ret;

	if (skb_is_gso(skb)) {
		/* SKB_GSO_UDP stays as is. SKB_GSO_TCPV6 needs to
		 * be changed into SKB_GSO_TCPV4.
		 */
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6) {
			skb_shinfo(skb)->gso_type &= ~SKB_GSO_TCPV6;
			skb_shinfo(skb)->gso_type |=  SKB_GSO_TCPV4;
		}

		/* Header must be checked, and gso_segs recomputed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	skb->protocol = htons(ETH_P_IP);
	skb->rxhash = 0;
	skb->l4_rxhash = 0;

	return 0;
}

static int bpf_skb_proto_xlat(struct sk_buff *skb, __be16 to_proto)
{
	__be16 from_proto = skb->protocol;

	if (from_proto == htons(ETH_P_IP) &&
	      to_proto == htons(ETH_P_IPV6))
		return bpf_skb_proto_4_to_6(skb);

	if (from_proto == htons(ETH_P_IPV6) &&
	      to_proto == htons(ETH_P_IP))
		return bpf_skb_proto_6_to_4(skb);

	return -ENOTSUPP;
}

BPF_CALL_3(bpf_skb_change_proto, struct sk_buff *, skb, __be16, proto,
	   u64, flags)
{
	int ret;

	if (unlikely(flags))
		return -EINVAL;

	/* General idea is that this helper does the basic groundwork
	 * needed for changing the protocol, and eBPF program fills the
	 * rest through bpf_skb_store_bytes(), bpf_lX_csum_replace()
	 * and other helpers, rather than passing a raw buffer here.
	 *
	 * The rationale is to keep this minimal and without a need to
	 * deal with raw packet data. F.e. even if we would pass buffers
	 * here, the program still needs to call the bpf_lX_csum_replace()
	 * helpers anyway. Plus, this way we keep also separation of
	 * concerns, since f.e. bpf_skb_store_bytes() should only take
	 * care of stores.
	 *
	 * Currently, additional options and extension header space are
	 * not supported, but flags register is reserved so we can adapt
	 * that. For offloads, we mark packet as dodgy, so that headers
	 * need to be verified first.
	 */
	ret = bpf_skb_proto_xlat(skb, proto);
	bpf_compute_data_end(skb);
	return ret;
}

static const struct bpf_func_proto bpf_skb_change_proto_proto = {
	.func		= bpf_skb_change_proto,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_skb_change_type, struct sk_buff *, skb, u32, pkt_type)
{
	/* We only allow a restricted subset to be changed for now. */
	if (unlikely(skb->pkt_type > PACKET_OTHERHOST ||
		     pkt_type > PACKET_OTHERHOST))
		return -EINVAL;

	skb->pkt_type = pkt_type;
	return 0;
}

static const struct bpf_func_proto bpf_skb_change_type_proto = {
	.func		= bpf_skb_change_type,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static u32 __bpf_skb_min_len(const struct sk_buff *skb)
{
	u32 min_len = skb_network_offset(skb);

	if (skb_transport_header_was_set(skb))
		min_len = skb_transport_offset(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		min_len = skb_checksum_start_offset(skb) +
			  skb->csum_offset + sizeof(__sum16);
	return min_len;
}

#define BPF_SKB_MAX_LEN SKB_MAX_ALLOC

static int bpf_skb_grow_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	unsigned int old_len = skb->len;
	int ret;

	ret = __skb_grow_rcsum(skb, new_len);
	if (!ret)
		memset(skb->data + old_len, 0, new_len - old_len);
	return ret;
}

static int bpf_skb_trim_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	return __skb_trim_rcsum(skb, new_len);
}

BPF_CALL_3(bpf_skb_change_tail, struct sk_buff *, skb, u32, new_len,
	   u64, flags)
{
	u32 max_len = BPF_SKB_MAX_LEN;
	u32 min_len = __bpf_skb_min_len(skb);
	int ret;

	if (unlikely(flags || new_len > max_len || new_len < min_len))
		return -EINVAL;

	/* The basic idea of this helper is that it's performing the
	 * needed work to either grow or trim an skb, and eBPF program
	 * rewrites the rest via helpers like bpf_skb_store_bytes(),
	 * bpf_lX_csum_replace() and others rather than passing a raw
	 * buffer here. This one is a slow path helper and intended
	 * for replies with control messages.
	 *
	 * Like in bpf_skb_change_proto(), we want to keep this rather
	 * minimal and without protocol specifics so that we are able
	 * to separate concerns as in bpf_skb_store_bytes() should only
	 * be the one responsible for writing buffers.
	 *
	 * It's really expected to be a slow path operation here for
	 * control message replies, so we're implicitly linearizing,
	 * uncloning and drop offloads from the skb by this.
	 */
	ret = __bpf_try_make_writable(skb, skb->len);
	if (!ret) {
		if (new_len > skb->len)
			ret = bpf_skb_grow_rcsum(skb, new_len);
		else if (new_len < skb->len)
			ret = bpf_skb_trim_rcsum(skb, new_len);
		if (!ret && skb_is_gso(skb))
			skb_gso_reset(skb);
	}

	bpf_compute_data_end(skb);
	return ret;
}

static const struct bpf_func_proto bpf_skb_change_tail_proto = {
	.func		= bpf_skb_change_tail,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

bool bpf_helper_changes_skb_data(void *func)
{
	if (func == bpf_skb_store_bytes ||
	    func == bpf_skb_change_proto ||
	    func == bpf_skb_change_tail ||
	    func == bpf_skb_pull_data ||
	    func == bpf_clone_redirect ||
	    func == bpf_l3_csum_replace ||
	    func == bpf_l4_csum_replace)
		return true;

	return false;
}

static unsigned long bpf_skb_copy(void *dst_buff, const void *skb,
				  unsigned long off, unsigned long len)
{
	void *ptr = skb_header_pointer(skb, off, len, dst_buff);

	if (unlikely(!ptr))
		return len;
	if (ptr != dst_buff)
		memcpy(dst_buff, ptr, len);

	return 0;
}

BPF_CALL_5(bpf_skb_event_output, struct sk_buff *, skb, struct bpf_map *, map,
	   u64, flags, void *, meta, u64, meta_size)
{
	u64 skb_size = (flags & BPF_F_CTXLEN_MASK) >> 32;

	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
		return -EINVAL;
	if (unlikely(skb_size > skb->len))
		return -EFAULT;

	return bpf_event_output(map, flags, meta, meta_size, skb, skb_size,
				bpf_skb_copy);
}

static const struct bpf_func_proto bpf_skb_event_output_proto = {
	.func		= bpf_skb_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_STACK,
	.arg5_type	= ARG_CONST_STACK_SIZE,
};

BPF_CALL_3(bpf_skb_under_cgroup, struct sk_buff *, skb, struct bpf_map *, map,
	   u32, idx)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct cgroup *cgrp;
	struct sock *sk;

	sk = skb->sk;
	if (!sk || !sk_fullsock(sk))
		return -ENOENT;
	if (unlikely(idx >= array->map.max_entries))
		return -E2BIG;

	cgrp = READ_ONCE(array->ptrs[idx]);
	if (unlikely(!cgrp))
		return -EAGAIN;

	return sk_under_cgroup_hierarchy(sk, cgrp);
}

static const struct bpf_func_proto bpf_skb_under_cgroup_proto = {
	.func		= bpf_skb_under_cgroup,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

static unsigned long bpf_xdp_copy(void *dst_buff, const void *src_buff,
				  unsigned long off, unsigned long len)
{
	memcpy(dst_buff, src_buff + off, len);
	return 0;
}

BPF_CALL_5(bpf_xdp_event_output, struct xdp_buff *, xdp, struct bpf_map *, map,
	   u64, flags, void *, meta, u64, meta_size)
{
	u64 xdp_size = (flags & BPF_F_CTXLEN_MASK) >> 32;

	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
		return -EINVAL;
	if (unlikely(xdp_size > (unsigned long)(xdp->data_end - xdp->data)))
		return -EFAULT;

	return bpf_event_output(map, flags, meta, meta_size, xdp, xdp_size,
				bpf_xdp_copy);
}

static const struct bpf_func_proto bpf_xdp_event_output_proto = {
	.func		= bpf_xdp_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_STACK,
	.arg5_type	= ARG_CONST_STACK_SIZE,
};

BPF_CALL_1(bpf_get_socket_cookie, struct sk_buff *, skb)
{
	return skb->sk ? sock_gen_cookie(skb->sk) : 0;
}

static const struct bpf_func_proto bpf_get_socket_cookie_proto = {
	.func           = bpf_get_socket_cookie,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_socket_uid, struct sk_buff *, skb)
{
	struct sock *sk = skb->sk;
	kuid_t kuid;

	if (!sk || !sk_fullsock(sk))
		return overflowuid;
	kuid = sock_net_uid(sock_net(sk), sk);
	return from_kuid_munged(sock_net(sk)->user_ns, kuid);
}

static const struct bpf_func_proto bpf_get_socket_uid_proto = {
	.func           = bpf_get_socket_uid,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

static const struct bpf_func_proto *
sk_filter_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_trace_printk:
		if (capable(CAP_SYS_ADMIN))
			return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_proto;
	default:
		return NULL;
	}
}

static const struct bpf_func_proto *
tc_cls_act_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_skb_store_bytes:
		return &bpf_skb_store_bytes_proto;
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_skb_pull_data:
		return &bpf_skb_pull_data_proto;
	case BPF_FUNC_csum_diff:
		return &bpf_csum_diff_proto;
	case BPF_FUNC_csum_update:
		return &bpf_csum_update_proto;
	case BPF_FUNC_l3_csum_replace:
		return &bpf_l3_csum_replace_proto;
	case BPF_FUNC_l4_csum_replace:
		return &bpf_l4_csum_replace_proto;
	case BPF_FUNC_clone_redirect:
		return &bpf_clone_redirect_proto;
	case BPF_FUNC_get_cgroup_classid:
		return &bpf_get_cgroup_classid_proto;
	case BPF_FUNC_skb_change_proto:
		return &bpf_skb_change_proto_proto;
	case BPF_FUNC_skb_change_type:
		return &bpf_skb_change_type_proto;
	case BPF_FUNC_skb_change_tail:
		return &bpf_skb_change_tail_proto;
	case BPF_FUNC_redirect:
		return &bpf_redirect_proto;
	case BPF_FUNC_get_route_realm:
		return &bpf_get_route_realm_proto;
	case BPF_FUNC_get_hash_recalc:
		return &bpf_get_hash_recalc_proto;
	case BPF_FUNC_set_hash_invalid:
		return &bpf_set_hash_invalid_proto;
	case BPF_FUNC_perf_event_output:
		return &bpf_skb_event_output_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_skb_under_cgroup:
		return &bpf_skb_under_cgroup_proto;
	default:
		return sk_filter_func_proto(func_id);
	}
}

static const struct bpf_func_proto *
xdp_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_xdp_event_output_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	default:
		return sk_filter_func_proto(func_id);
	}
}

static const struct bpf_func_proto *
cg_skb_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	default:
		return sk_filter_func_proto(func_id);
	}
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type)
{
	if (off < 0 || off >= sizeof(struct __sk_buff))
		return false;
	/* The verifier guarantees that size > 0. */
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static bool sk_filter_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      enum bpf_reg_type *reg_type)
{
	switch (off) {
	case offsetof(struct __sk_buff, tc_classid):
	case offsetof(struct __sk_buff, data):
	case offsetof(struct __sk_buff, data_end):
		return false;
	}

	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct __sk_buff, cb[0]) ...
		     offsetof(struct __sk_buff, cb[4]):
			break;
		default:
			return false;
		}
	}

	return __is_valid_access(off, size, type);
}

static int tc_cls_act_prologue(struct bpf_insn *insn_buf, bool direct_write,
			       const struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	if (!direct_write)
		return 0;

	/* if (!skb->cloned)
	 *       goto start;
	 *
	 * (Fast-path, otherwise approximation that we might be
	 *  a clone, do the rest in helper.)
	 */
	*insn++ = BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_1, CLONED_OFFSET());
	*insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, CLONED_MASK);
	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 7);

	/* ret = bpf_skb_pull_data(skb, 0); */
	*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
	*insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_2, BPF_REG_2);
	*insn++ = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			       BPF_FUNC_skb_pull_data);
	/* if (!ret)
	 *      goto restore;
	 * return TC_ACT_SHOT;
	 */
	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2);
	*insn++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, TC_ACT_SHOT);
	*insn++ = BPF_EXIT_INSN();

	/* restore: */
	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
	/* start: */
	*insn++ = prog->insnsi[0];

	return insn - insn_buf;
}

static bool tc_cls_act_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       enum bpf_reg_type *reg_type)
{
	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct __sk_buff, mark):
		case offsetof(struct __sk_buff, tc_index):
		case offsetof(struct __sk_buff, priority):
		case offsetof(struct __sk_buff, cb[0]) ...
		     offsetof(struct __sk_buff, cb[4]):
		case offsetof(struct __sk_buff, tc_classid):
			break;
		default:
			return false;
		}
	}

	switch (off) {
	case offsetof(struct __sk_buff, data):
		*reg_type = PTR_TO_PACKET;
		break;
	case offsetof(struct __sk_buff, data_end):
		*reg_type = PTR_TO_PACKET_END;
		break;
	}

	return __is_valid_access(off, size, type);
}

static bool __is_valid_xdp_access(int off, int size,
				  enum bpf_access_type type)
{
	if (off < 0 || off >= sizeof(struct xdp_md))
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static bool xdp_is_valid_access(int off, int size,
				enum bpf_access_type type,
				enum bpf_reg_type *reg_type)
{
	if (type == BPF_WRITE)
		return false;

	switch (off) {
	case offsetof(struct xdp_md, data):
		*reg_type = PTR_TO_PACKET;
		break;
	case offsetof(struct xdp_md, data_end):
		*reg_type = PTR_TO_PACKET_END;
		break;
	}

	return __is_valid_xdp_access(off, size, type);
}

void bpf_warn_invalid_xdp_action(u32 act)
{
	WARN_ONCE(1, "Illegal XDP return value %u, expect packet loss\n", act);
}
EXPORT_SYMBOL_GPL(bpf_warn_invalid_xdp_action);

static u32 sk_filter_convert_ctx_access(enum bpf_access_type type, int dst_reg,
					int src_reg, int ctx_off,
					struct bpf_insn *insn_buf,
					struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	switch (ctx_off) {
	case offsetof(struct __sk_buff, len):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, len) != 4);

		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
				      offsetof(struct sk_buff, len));
		break;

	case offsetof(struct __sk_buff, protocol):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, protocol) != 2);

		*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
				      offsetof(struct sk_buff, protocol));
		break;

	case offsetof(struct __sk_buff, priority):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, priority) != 4);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, dst_reg, src_reg,
					      offsetof(struct sk_buff, priority));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
					      offsetof(struct sk_buff, priority));
		break;

	case offsetof(struct __sk_buff, ingress_ifindex):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, skb_iif) != 4);

		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
				      offsetof(struct sk_buff, skb_iif));
		break;

	case offsetof(struct __sk_buff, ifindex):
		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
				      dst_reg, src_reg,
				      offsetof(struct sk_buff, dev));
		*insn++ = BPF_JMP_IMM(BPF_JEQ, dst_reg, 0, 1);
		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, dst_reg,
				      offsetof(struct net_device, ifindex));
		break;

	case offsetof(struct __sk_buff, hash):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, rxhash) != 4);

		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
				      offsetof(struct sk_buff, rxhash));
		break;

	case offsetof(struct __sk_buff, mark):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, mark) != 4);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, dst_reg, src_reg,
					      offsetof(struct sk_buff, mark));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
					      offsetof(struct sk_buff, mark));
		break;

	case offsetof(struct __sk_buff, pkt_type):
		return convert_skb_access(SKF_AD_PKTTYPE, dst_reg, src_reg, insn);

	case offsetof(struct __sk_buff, queue_mapping):
		return convert_skb_access(SKF_AD_QUEUE, dst_reg, src_reg, insn);

	case offsetof(struct __sk_buff, vlan_present):
		return convert_skb_access(SKF_AD_VLAN_TAG_PRESENT,
					  dst_reg, src_reg, insn);

	case offsetof(struct __sk_buff, vlan_tci):
		return convert_skb_access(SKF_AD_VLAN_TAG,
					  dst_reg, src_reg, insn);

	case offsetof(struct __sk_buff, cb[0]) ...
	     offsetof(struct __sk_buff, cb[4]):
		BUILD_BUG_ON(FIELD_SIZEOF(struct qdisc_skb_cb, data) < 20);

		prog->cb_access = 1;
		ctx_off -= offsetof(struct __sk_buff, cb[0]);
		ctx_off += offsetof(struct sk_buff, cb);
		ctx_off += offsetof(struct qdisc_skb_cb, data);
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, dst_reg, src_reg, ctx_off);
		else
			*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg, ctx_off);
		break;

	case offsetof(struct __sk_buff, tc_classid):
		ctx_off -= offsetof(struct __sk_buff, tc_classid);
		ctx_off += offsetof(struct sk_buff, cb);
		ctx_off += offsetof(struct qdisc_skb_cb, tc_classid);
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_H, dst_reg, src_reg, ctx_off);
		else
			*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg, ctx_off);
		break;

	case offsetof(struct __sk_buff, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, data),
				      dst_reg, src_reg,
				      offsetof(struct sk_buff, data));
		break;

	case offsetof(struct __sk_buff, data_end):
		ctx_off -= offsetof(struct __sk_buff, data_end);
		ctx_off += offsetof(struct sk_buff, cb);
		ctx_off += offsetof(struct bpf_skb_data_end, data_end);
		*insn++ = BPF_LDX_MEM(BPF_SIZEOF(void *), dst_reg, src_reg,
				      ctx_off);
		break;

	case offsetof(struct __sk_buff, tc_index):
#ifdef CONFIG_NET_SCHED
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, tc_index) != 2);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_H, dst_reg, src_reg,
					      offsetof(struct sk_buff, tc_index));
		else
			*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
					      offsetof(struct sk_buff, tc_index));
		break;
#else
		if (type == BPF_WRITE)
			*insn++ = BPF_MOV64_REG(dst_reg, dst_reg);
		else
			*insn++ = BPF_MOV64_IMM(dst_reg, 0);
		break;
#endif
	}

	return insn - insn_buf;
}

static u32 tc_cls_act_convert_ctx_access(enum bpf_access_type type, int dst_reg,
					 int src_reg, int ctx_off,
					 struct bpf_insn *insn_buf,
					 struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	switch (ctx_off) {
	case offsetof(struct __sk_buff, ifindex):
		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
				      dst_reg, src_reg,
				      offsetof(struct sk_buff, dev));
		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, dst_reg,
				      offsetof(struct net_device, ifindex));
		break;
	default:
		return sk_filter_convert_ctx_access(type, dst_reg, src_reg,
						    ctx_off, insn_buf, prog);
	}

	return insn - insn_buf;
}

static u32 xdp_convert_ctx_access(enum bpf_access_type type, int dst_reg,
				  int src_reg, int ctx_off,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	switch (ctx_off) {
	case offsetof(struct xdp_md, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data),
				      dst_reg, src_reg,
				      offsetof(struct xdp_buff, data));
		break;
	case offsetof(struct xdp_md, data_end):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data_end),
				      dst_reg, src_reg,
				      offsetof(struct xdp_buff, data_end));
		break;
	}

	return insn - insn_buf;
}

static const struct bpf_verifier_ops sk_filter_ops = {
	.get_func_proto		= sk_filter_func_proto,
	.is_valid_access	= sk_filter_is_valid_access,
	.convert_ctx_access	= sk_filter_convert_ctx_access,
};

static const struct bpf_verifier_ops tc_cls_act_ops = {
	.get_func_proto		= tc_cls_act_func_proto,
	.is_valid_access	= tc_cls_act_is_valid_access,
	.convert_ctx_access	= tc_cls_act_convert_ctx_access,
	.gen_prologue		= tc_cls_act_prologue,
};

static const struct bpf_verifier_ops xdp_ops = {
	.get_func_proto		= xdp_func_proto,
	.is_valid_access	= xdp_is_valid_access,
	.convert_ctx_access	= xdp_convert_ctx_access,
};

static const struct bpf_verifier_ops cg_skb_ops = {
	.get_func_proto		= cg_skb_func_proto,
	.is_valid_access	= sk_filter_is_valid_access,
	.convert_ctx_access	= sk_filter_convert_ctx_access,
};

static struct bpf_prog_type_list sk_filter_type __read_mostly = {
	.ops	= &sk_filter_ops,
	.type	= BPF_PROG_TYPE_SOCKET_FILTER,
};

static struct bpf_prog_type_list sched_cls_type __read_mostly = {
	.ops	= &tc_cls_act_ops,
	.type	= BPF_PROG_TYPE_SCHED_CLS,
};

static struct bpf_prog_type_list sched_act_type __read_mostly = {
	.ops	= &tc_cls_act_ops,
	.type	= BPF_PROG_TYPE_SCHED_ACT,
};

static struct bpf_prog_type_list xdp_type __read_mostly = {
	.ops	= &xdp_ops,
	.type	= BPF_PROG_TYPE_XDP,
};

static struct bpf_prog_type_list cg_skb_type __read_mostly = {
	.ops	= &cg_skb_ops,
	.type	= BPF_PROG_TYPE_CGROUP_SKB,
};

static int __init register_sk_filter_ops(void)
{
	bpf_register_prog_type(&sk_filter_type);
	bpf_register_prog_type(&sched_cls_type);
	bpf_register_prog_type(&sched_act_type);
	bpf_register_prog_type(&xdp_type);
	bpf_register_prog_type(&cg_skb_type);

	return 0;
}
late_initcall(register_sk_filter_ops);

int sk_detach_filter(struct sock *sk)
{
	int ret = -ENOENT;
	struct sk_filter *filter;

	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return -EPERM;

	filter = rcu_dereference_protected(sk->sk_filter,
					   sock_owned_by_user(sk));
	if (filter) {
		RCU_INIT_POINTER(sk->sk_filter, NULL);
		sk_filter_uncharge(sk, filter);
		ret = 0;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sk_detach_filter);

void sk_decode_filter(struct sock_filter *filt, struct sock_filter *to)
{
	static const u16 decodes[] = {
		[BPF_S_ALU_ADD_K]	= BPF_ALU|BPF_ADD|BPF_K,
		[BPF_S_ALU_ADD_X]	= BPF_ALU|BPF_ADD|BPF_X,
		[BPF_S_ALU_SUB_K]	= BPF_ALU|BPF_SUB|BPF_K,
		[BPF_S_ALU_SUB_X]	= BPF_ALU|BPF_SUB|BPF_X,
		[BPF_S_ALU_MUL_K]	= BPF_ALU|BPF_MUL|BPF_K,
		[BPF_S_ALU_MUL_X]	= BPF_ALU|BPF_MUL|BPF_X,
		[BPF_S_ALU_DIV_X]	= BPF_ALU|BPF_DIV|BPF_X,
		[BPF_S_ALU_MOD_K]	= BPF_ALU|BPF_MOD|BPF_K,
		[BPF_S_ALU_MOD_X]	= BPF_ALU|BPF_MOD|BPF_X,
		[BPF_S_ALU_AND_K]	= BPF_ALU|BPF_AND|BPF_K,
		[BPF_S_ALU_AND_X]	= BPF_ALU|BPF_AND|BPF_X,
		[BPF_S_ALU_OR_K]	= BPF_ALU|BPF_OR|BPF_K,
		[BPF_S_ALU_OR_X]	= BPF_ALU|BPF_OR|BPF_X,
		[BPF_S_ALU_XOR_K]	= BPF_ALU|BPF_XOR|BPF_K,
		[BPF_S_ALU_XOR_X]	= BPF_ALU|BPF_XOR|BPF_X,
		[BPF_S_ALU_LSH_K]	= BPF_ALU|BPF_LSH|BPF_K,
		[BPF_S_ALU_LSH_X]	= BPF_ALU|BPF_LSH|BPF_X,
		[BPF_S_ALU_RSH_K]	= BPF_ALU|BPF_RSH|BPF_K,
		[BPF_S_ALU_RSH_X]	= BPF_ALU|BPF_RSH|BPF_X,
		[BPF_S_ALU_NEG]		= BPF_ALU|BPF_NEG,
		[BPF_S_LD_W_ABS]	= BPF_LD|BPF_W|BPF_ABS,
		[BPF_S_LD_H_ABS]	= BPF_LD|BPF_H|BPF_ABS,
		[BPF_S_LD_B_ABS]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_PROTOCOL]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_PKTTYPE]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_IFINDEX]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_NLATTR]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_NLATTR_NEST]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_MARK]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_QUEUE]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_HATYPE]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_RXHASH]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_CPU]		= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_ALU_XOR_X]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_SECCOMP_LD_W] = BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_VLAN_TAG]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_VLAN_TAG_PRESENT] = BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_ANC_PAY_OFFSET]	= BPF_LD|BPF_B|BPF_ABS,
		[BPF_S_LD_W_LEN]	= BPF_LD|BPF_W|BPF_LEN,
		[BPF_S_LD_W_IND]	= BPF_LD|BPF_W|BPF_IND,
		[BPF_S_LD_H_IND]	= BPF_LD|BPF_H|BPF_IND,
		[BPF_S_LD_B_IND]	= BPF_LD|BPF_B|BPF_IND,
		[BPF_S_LD_IMM]		= BPF_LD|BPF_IMM,
		[BPF_S_LDX_W_LEN]	= BPF_LDX|BPF_W|BPF_LEN,
		[BPF_S_LDX_B_MSH]	= BPF_LDX|BPF_B|BPF_MSH,
		[BPF_S_LDX_IMM]		= BPF_LDX|BPF_IMM,
		[BPF_S_MISC_TAX]	= BPF_MISC|BPF_TAX,
		[BPF_S_MISC_TXA]	= BPF_MISC|BPF_TXA,
		[BPF_S_RET_K]		= BPF_RET|BPF_K,
		[BPF_S_RET_A]		= BPF_RET|BPF_A,
		[BPF_S_ALU_DIV_K]	= BPF_ALU|BPF_DIV|BPF_K,
		[BPF_S_LD_MEM]		= BPF_LD|BPF_MEM,
		[BPF_S_LDX_MEM]		= BPF_LDX|BPF_MEM,
		[BPF_S_ST]		= BPF_ST,
		[BPF_S_STX]		= BPF_STX,
		[BPF_S_JMP_JA]		= BPF_JMP|BPF_JA,
		[BPF_S_JMP_JEQ_K]	= BPF_JMP|BPF_JEQ|BPF_K,
		[BPF_S_JMP_JEQ_X]	= BPF_JMP|BPF_JEQ|BPF_X,
		[BPF_S_JMP_JGE_K]	= BPF_JMP|BPF_JGE|BPF_K,
		[BPF_S_JMP_JGE_X]	= BPF_JMP|BPF_JGE|BPF_X,
		[BPF_S_JMP_JGT_K]	= BPF_JMP|BPF_JGT|BPF_K,
		[BPF_S_JMP_JGT_X]	= BPF_JMP|BPF_JGT|BPF_X,
		[BPF_S_JMP_JSET_K]	= BPF_JMP|BPF_JSET|BPF_K,
		[BPF_S_JMP_JSET_X]	= BPF_JMP|BPF_JSET|BPF_X,
	};
	u16 code;

	code = filt->code;

	to->code = decodes[code];
	to->jt = filt->jt;
	to->jf = filt->jf;

	if (code == BPF_S_ALU_DIV_K) {
		/*
		 * When loaded this rule user gave us X, which was
		 * translated into R = r(X). Now we calculate the
		 * RR = r(R) and report it back. If next time this
		 * value is loaded and RRR = r(RR) is calculated
		 * then the R == RRR will be true.
		 *
		 * One exception. X == 1 translates into R == 0 and
		 * we can't calculate RR out of it with r().
		 */

		if (filt->k == 0)
			to->k = 1;
		else
			to->k = reciprocal_value(filt->k);

		BUG_ON(reciprocal_value(to->k) != filt->k);
	} else
		to->k = filt->k;
}

int sk_get_filter(struct sock *sk, struct sock_filter __user *ubuf, unsigned int len)
{
	struct sk_filter *filter;
	int i, ret;

	lock_sock(sk);
	filter = rcu_dereference_protected(sk->sk_filter,
			sock_owned_by_user(sk));
	ret = 0;
	if (!filter)
		goto out;
	ret = filter->len;
	if (!len)
		goto out;
	ret = -EINVAL;
	if (len < filter->len)
		goto out;

	ret = -EFAULT;
	for (i = 0; i < filter->len; i++) {
		struct sock_filter fb;

		sk_decode_filter(&filter->insns[i], &fb);
		if (copy_to_user(&ubuf[i], &fb, sizeof(fb)))
			goto out;
	}

	ret = filter->len;
out:
	release_sock(sk);
	return ret;
}
