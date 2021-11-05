#include "1m-block.h"
char* strnstr(const char *big, const char *little, size_t len)
{
    size_t i,temp;
    i=0;
    while(big[i]&&i<len) {
        temp=0;
        if(little[temp]==big[i+temp]) {
            while(little[temp]&&big[i+temp]) {
                if(little[temp]!=big[i+temp]||(i+temp)>=len) break;
                temp++;
            }
            if(little[temp]=='\0') return (&((char *)big)[i]);
        }
        i++;
    }
    return (NULL);
}
const uint64_t mod=1e9+7;
uint64_t rabin_karp(std::string s, size_t l, size_t r)
{
    uint64_t hash=0;
    for(size_t i = l; i <= r; i++) {
        hash<<=1;
        hash+=s[i]-'!'+1;
        hash%=mod;
    }
    return hash;
}
