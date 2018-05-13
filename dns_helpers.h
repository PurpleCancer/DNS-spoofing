#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct domain
{
    char len;
    char * content;
    struct domain * next;
};

void delete_domain_struct(struct domain * d);

void insert_at_end(struct domain * list, struct domain * el);

struct domain * domain_struct_from_domain_name(char * name);
struct domain * domain_struct_from_dns_query(char * query);
char * dns_query_from_domain_struct(struct domain * d);

int compare_domain_structs(struct domain * d1, struct domain * d2);