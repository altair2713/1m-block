#pragma once
#include <string.h>
#include <string>
struct node {
    bool valid;
    int child['~'-'!'+1],child_cnt,len;
    uint64_t hash;
    node() {
        valid=false;
        child_cnt=0;
        memset(child,-1,sizeof(child));
    }
};
char* strnstr(const char *big, const char *little, size_t len);
uint64_t rabin_karp(std::string s, size_t l, size_t r);
