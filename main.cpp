#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <tuple>
#include <1m-block.h>
char method[9][10]={"TRACE","PATCH","HEAD","PUT","DELETE","CONNECT","OPTIONS","POST","GET"};
int method_len[9]={5,5,4,3,6,7,7,4,3};
const uint64_t mod=1e9+7;
const int site_num=560405;
std::vector<uint64_t> block;
std::vector<node> trie;
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if(i != 0 && i % 16 == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    //struct nfqnl_msg_packet_hw *hwph;
    //u_int32_t mark,ifi;
    //int ret;
    //unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ",
            //ntohs(ph->hw_protocol), ph->hook, id);
    }
/*
    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
        dump(data,ret);
    }

    fputc('\n', stdout);
*/
    return id;
}
void add(std::string s)
{
    int cur=0;
    for(size_t i = 0; i < s.length(); i++) {
        int idx=s[i]-'!';
        if(i==s.length()-1) {
            trie[cur].valid=true;
            return;
        }
        if(trie[cur].child[idx]==-1) {
            trie[cur].child_cnt++;
            node temp;
            trie.push_back(temp);
            int next=(int)trie.size()-1;
            trie[cur].child[idx]=next;
        }
        cur=trie[cur].child[idx];
    }
    return;
}
void make_trie(char* file)
{
    FILE* fp=fopen(file,"rb");
    char buffer[1000];
    for(int i=site_num; i--; ) {
        fscanf(fp,"%s",buffer);
        std::string str(buffer);
        memset(buffer,0,sizeof(buffer));
        add(str);
    }
    fclose(fp);
    return;
}
std::tuple<int,int,uint64_t> dfs(int cur, int length, uint64_t hash)
{
    if(trie[cur].valid||trie[cur].child_cnt>1) return {cur,length,hash};
    for(int i = 0; i <= '~'-'!'; i++) if(trie[cur].child[i]!=-1) return dfs(trie[cur].child[i],length+1,(hash*2+i+1)%mod);
    return {};
}
void compress_trie(int cur)
{
    for(int i = 0; i <= '~'-'!'; i++) {
        if(trie[cur].child[i]!=-1) {
            auto[next,length,hash]=dfs(trie[cur].child[i],1,i+1);
            trie[cur].child[i]=next;
            trie[next].len=length;
            trie[next].hash=hash;
            compress_trie(next);
        }
    }
    return;
}
bool search(std::string host)
{
    int cur=0;
    size_t idx=0;
    while(1) {
        if(idx==host.length()-1) {
            if(trie[cur].valid) return true;
            break;
        }
        int next=trie[cur].child[host[idx]-'!'];
        if(next==-1) break;
        int length=trie[next].len;
        if(idx+length>host.length()) break;
        if(trie[next].hash==rabin_karp(host,idx,idx+length-1)) {
            cur=next;
            idx+=length;
        }
        else break;
    }
    return false;
}
bool is_block(struct nfq_data *nfa)
{
    u_char* packet;
    uint32_t packet_len=nfq_get_payload(nfa,&packet);
    if(!packet_len) return false;
    struct libnet_ipv4_hdr* ip=(struct libnet_ipv4_hdr*)packet;
    if(ip->ip_p!=IPPROTO_TCP) return false;
    uint32_t ip_len=4*(uint32_t)ip->ip_hl;
    if(packet_len==ip_len) return false;
    struct libnet_tcp_hdr* tcp=(struct libnet_tcp_hdr*)(packet+ip_len);
    if(htons(tcp->th_dport)!=80) return false;
    uint32_t tcp_len=4*(uint32_t)tcp->th_off;
    uint32_t packet_offset=ip_len+tcp_len;
    if(packet_len==packet_offset) return false;
    char* http=(char*)(packet+packet_offset);
    bool flag=0;
    for(int i=9; i--; ) {
        if(strncmp(http,method[i],method_len[i])) continue;
        flag=1;
        break;
    }
    if(!flag) return false;
    char s[10]="Host: ";
    int len=strlen(http);
    char* ret=strnstr(http,s,std::min(len,1000));
    if(ret) {
        std::string host;
        for(int i = 6; ret[i]!='\r'; i++) host.push_back(ret[i]);
        bool ret=search(host);
        if(ret) {
            std::cout << "We filtered : " << host << '\n';
            return true;
        }
    }
    return false;
}
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    bool ret=is_block(nfa);
    if(ret) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
int main(int argc, char **argv)
{
    if(argc!=2) {
        printf("usage : 1m-block <site list file>\n");
        printf("sample : 1m-block top-1m.txt");
        exit(1);
    }
    node tmp;
    trie.push_back(tmp);
    make_trie(argv[1]);
    compress_trie(0);
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
