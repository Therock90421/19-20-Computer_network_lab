#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct IP_entry {
	uint32_t ip;
	uint32_t mask;
	uint32_t port;
} IP_entry;

typedef struct TNode {
	struct TNode *LChild, *RChild;
	uint32_t port;
} TNode, *Tree;

typedef struct TNode_zip {
	struct TNode_zip *LChild, *RChild ;
	uint32_t Lnum;
	uint32_t L_mask;
	uint32_t Rnum;
	uint32_t R_mask;
	uint32_t port;
	uint32_t unzipable;
} TNode_zip, *Tree_zip;

typedef struct Tnode_2bit {
	struct Tnode_2bit *Child00, *Child01, *Child10, *Child11;
	uint32_t port;
} Tnode_2bit, *Tree_2bits;


char *source = "forwarding-table.txt";
char *test = "test-table.txt";
