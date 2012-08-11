/******************************************************************************

    Programmer:  Erin Johnson
	email: erin@underscorehayling.com
	date:  Aug. 11, 2012
	Program name: netlag
	Description:  Linux kernel module to simulate geographically large networks 
				  by introducing a lag to a incoming targeted IP
	Disclaimer:  This code is provided as is, use at your own risk. 
	License:  Dual BSD GPL

******************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/hrtimer.h>
#include <linux/ktime.h>

#include <linux/slab.h>

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_queue.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/skbuff.h>


MODULE_LICENSE("Dual BSD/GPL");

//got this from an hrtimers example
#define MS_TO_NS(x)	(x * 1E6L)


static struct nf_hook_ops netfilter_ops;

//values we get from when module is loaded
static char * ip = "000.000.000.000";
module_param(ip, charp, 0);

unsigned long delay = 300L; //in ms
module_param(delay, ulong, 0);


//what ip and delay get converted to in init
__be32 ip_address;
static ktime_t packet_delay;

/*
	This struct is needed because hrtimers do not allow you to pass data
	too the callback function.  However, by nesting the hrtimer in this
	struct we can use container_of on the hrtimer to get access to the
	info we want.
	
*/
struct packet_data{
	struct hrtimer delay_timer;
	struct sk_buff *skb;
	int  (*okfn)(struct sk_buff *);

};


//used for cleaning up and freeing memory as we go so we don't leak
static struct hrtimer * hrtimer_to_cancel;
static struct packet_data * pd_to_free;


enum hrtimer_restart send_delayed_packet( struct hrtimer *timer ){
  
	struct packet_data *  pd;
	pd = container_of(timer, struct packet_data , delay_timer);

	//you can't cancel a timer while you are in its callback function so,
	//we cancel it the next time a timer times out
	if(hrtimer_to_cancel){
		hrtimer_cancel(hrtimer_to_cancel);
		kfree(pd_to_free);
	}
	pd_to_free = pd;
	hrtimer_to_cancel = timer;
	

	/* 
	   kind of tricking the hook here. tossing the packet to be checked at the 
	   NF_INET_LOCAL_IN hook, however the okfn is a function pointer for the 
	   next step after the packet comes in raw therefore it SHOULD be processed 
	   correctly should it need to be routed elsewhere and isn't meant for the 
	   host.  If we try to reinject it at the same hook we grabbed it gets stuck
	   in an infinite loop.
	 */
	
	NF_HOOK(PF_INET, NF_INET_LOCAL_IN, pd->skb, pd->skb->dev, NULL, pd->okfn);
	

  return HRTIMER_NORESTART;
}


unsigned int packet_filter_hook(unsigned int hooknum, struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff*)){
	
	struct packet_data * pd;

	if(!skb){ return NF_ACCEPT; }
	
	//block everything or just a specific IP
	if(ip_address == 0 || ip_hdr(skb)->saddr == ip_address){

		pd = (struct packet_data *) kmalloc(sizeof(struct packet_data), GFP_ATOMIC);
		
		//Copy skb and callback function so that we can use it later	
		pd->skb = skb_copy(skb, GFP_ATOMIC);
		pd->okfn = okfn;

		//set up the hrtimer
		hrtimer_init( &pd->delay_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
		pd->delay_timer.function = &send_delayed_packet;
		hrtimer_start( &pd->delay_timer, packet_delay, HRTIMER_MODE_REL );

		//lets the kernel know that we've taken care of the packet       	 	
		return NF_STOLEN;
  	}


	return NF_ACCEPT;
}

int init_module( void ){

	hrtimer_to_cancel=NULL;
	pd_to_free=NULL;

	packet_delay= ktime_set( 0, MS_TO_NS(delay) );

	//converts ip from dot notation to hlong
	ip_address=in_aton(ip);

	netfilter_ops.hook              =       packet_filter_hook;
	netfilter_ops.pf                =       PF_INET;
	netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
	netfilter_ops.priority          =       NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops);

	return 0;
}

void cleanup_module( void ){
  
 	nf_unregister_hook(&netfilter_ops);

	if(hrtimer_to_cancel){
                hrtimer_cancel(hrtimer_to_cancel);
                kfree(pd_to_free);
	}
}
