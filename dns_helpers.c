#include "dns_helpers.h"

void delete_domain_struct(struct domain * d)
{
    while(d != NULL)
    {
        free(d->content);
        struct domain * old = d;
        d = d->next;
        free(old);
    }
}

void insert_at_end(struct domain * list, struct domain * el)
{
    if (list == NULL)
    {
        return;
    }
    while(list->next != NULL)
    {
        list = list->next;
    }
    list->next = el;
}

struct domain * domain_struct_from_domain_name(char * name)
{
    int i;
    struct domain * d = NULL;
    int dot = strcspn(name, ".");
    while (dot < strlen(name))
    {
        struct domain * new_node = malloc(sizeof(struct domain));
        new_node->len = dot;
        new_node->content = malloc(dot + 1);
        new_node->next = NULL;

        for (i = 0; i < dot; ++i)
        {
            new_node->content[i] = name[i];
        }
        new_node->content[dot] = '\0';
        name = name + dot + 1;

        if (d == NULL)
        {
            d = new_node;
        }
        else
        {
            insert_at_end(d, new_node);
        }

        dot = strcspn(name, ".");
    }

    struct domain * new_node = malloc(sizeof(struct domain));
    new_node->len = strlen(name);
    new_node->content = malloc(strlen(name) + 1);
    strcpy(new_node->content, name);
    new_node->next = NULL;

    if (d == NULL)
    {
        d = new_node;
    }
    else
    {
        insert_at_end(d, new_node);
    }

    return d;
}

struct domain * domain_struct_from_dns_query(char * query)
{
    int i;
    char len;
    char * c;
    struct domain * d = NULL;
    c = query;
    while (*c != '\0')
    {
        struct domain * new_node = malloc(sizeof(struct domain));
        len = *c;
        new_node->len = len;
        new_node->content = malloc(len + 1);
        new_node->next = NULL;
        for (i = 0; i < len; ++i)
        {
            c++;
            new_node->content[i] = *c;
        }
        new_node->content[(int)len] = '\0';
        c++;

        if (d == NULL)
        {
            d = new_node;
        }
        else
        {
            insert_at_end(d, new_node);
        }
    }

    return d;
}

char * dns_query_from_domain_struct(struct domain * d)
{
    int i, j;
    int len = 0;
    struct domain * enumerator = d;
    while (enumerator != NULL)
    {
        len = len + enumerator->len + 1;
        enumerator = enumerator->next;
    }

    char * query = malloc(len + 1);
    i = 0;
    while (d != NULL)
    {
        query[i++] = d->len;
        for (j = 0; j < d->len; ++j, ++i)
        {
            query[i] = d->content[j];
        }
        d = d->next;
    }
    query[i+1] = '\0';

    return query;
}

int compare_domain_structs(struct domain * d1, struct domain * d2)
{
    while (d1 != NULL && d2 != NULL)
    {
        if (d1 == NULL || d2 == NULL)
            return -1;

        int c = strcmp(d1->content, d2->content);
        if (c != 0)
            return c;

        d1 = d1->next;
        d2 = d2->next;
    }

    return 0;
}