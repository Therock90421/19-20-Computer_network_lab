#include "pref-tree.h"
int err = 0;
void Error(uint32_t port, IP_entry *ip_entry) 
{
	err++;
	printf("IP %u.%u.%u.%u,  search result is wrong.\n  ", \
		ip_entry->ip>>24, (ip_entry->ip>>16)&0xff, (ip_entry->ip>>8)&0xff, ip_entry->ip&0xff);
	printf("Refference port = %u, search result is %u \n", port , ip_entry->port);
}

void build_prefix_tree(Tree prefix_tree) 
{
	prefix_tree->port = 255;
	FILE *fp = fopen(source, "r");
	uint32_t ip_pointer = 1 << 31;
	TNode *node = NULL;
	IP_entry *ip_entry = (IP_entry*)malloc(sizeof(IP_entry));
	char s[25];

	while (1)
	 {
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
		int i = 0;
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];
		node = prefix_tree;

		int IP_bit[32] = {0};
		for(i = 0; i < 32; i++)
		{
			IP_bit[i] = ip_entry->ip & (ip_pointer >> i);
			if(i >= ip_entry->mask)
			    IP_bit[i] = -1;
		}
		for (int j = 0; j < ip_entry->mask; j++) 
		{
			if (IP_bit[j]) {
				if (!node->RChild) 
				{
					TNode *tmp_node = (TNode*)malloc(sizeof(TNode));
					tmp_node->LChild = tmp_node->RChild = NULL;
					tmp_node->port = node->port;
					node->RChild = tmp_node;
				}
				node = node->RChild;
			} 
			else 
			{
				if (!node->LChild) 
				{
					TNode *tmp_node = (TNode*)malloc(sizeof(TNode));
					tmp_node->LChild = tmp_node->RChild = NULL;
					tmp_node->port = node->port;
					node->LChild = tmp_node;
				}
				node = node->LChild;
			}
		}
		node->port = ip_entry->port;
	}
	fclose(fp);
}
int count_zipable = 0;
void sign_zipable(Tree_zip prefix_tree)
{
    int i = 0;
	if(prefix_tree->LChild)
	{
		i++;
		sign_zipable(prefix_tree->LChild);
	}
	if(prefix_tree->RChild)
	{
		i++;
		sign_zipable(prefix_tree->RChild);
	}
	if(i == 2 || i == 0) prefix_tree->unzipable = 1;
	count_zipable = (prefix_tree->unzipable)? count_zipable:count_zipable+1; 
}
void tree_zip(Tree_zip prefix_tree)
{
	if(prefix_tree->LChild)
	{
	    if(!prefix_tree->LChild->unzipable)  //left child node can be zipped
		{
			if(prefix_tree->LChild->LChild)
			{
			    if(!prefix_tree->LChild->RChild)
				{
					TNode_zip *tmp_node = prefix_tree->LChild;
					prefix_tree->LChild = tmp_node->LChild;
					prefix_tree->Lnum = prefix_tree->Lnum + 1;
					prefix_tree->L_mask = (prefix_tree->L_mask << 1) + 0;
					free(tmp_node);
					tree_zip(prefix_tree);
				}
				else 
				{
					prefix_tree->LChild->unzipable = 1;
					tree_zip(prefix_tree->LChild);
				}
			}
			else
			{
				if(!prefix_tree->LChild->RChild)
				{
					return;
				}
				else 
				{
					TNode_zip *tmp_node = prefix_tree->LChild;
					prefix_tree->LChild = tmp_node->RChild;
					prefix_tree->Lnum = prefix_tree->Lnum + 1;
					prefix_tree->L_mask = (prefix_tree->L_mask << 1) + 1;
					free(tmp_node);
					tree_zip(prefix_tree);
				}
			}
			
		}
		else
		{
			tree_zip(prefix_tree->LChild);
		}
	}
	if(prefix_tree->RChild)
	{
	    if(!prefix_tree->RChild->unzipable)  //right child node can be zipped
		{
			if(prefix_tree->RChild->LChild)
			{
			    if(!prefix_tree->RChild->RChild)
				{
					TNode_zip *tmp_node = prefix_tree->RChild;
					prefix_tree->RChild = tmp_node->LChild;
					prefix_tree->Rnum = prefix_tree->Rnum + 1;
					prefix_tree->R_mask = (prefix_tree->R_mask << 1) + 0;
					free(tmp_node);
					tree_zip(prefix_tree);
				}
				else 
				{
					prefix_tree->RChild->unzipable = 1;
					tree_zip(prefix_tree->RChild);
				}
			}
			else
			{
				if(!prefix_tree->RChild->RChild)
				{
					return;
				}
				else 
				{
					TNode_zip *tmp_node = prefix_tree->RChild;
					prefix_tree->RChild = tmp_node->RChild;
					prefix_tree->Rnum++;
					prefix_tree->R_mask = (prefix_tree->R_mask << 1) + 1;
					free(tmp_node);
					tree_zip(prefix_tree);
				}
				
			}
			
		}
		else
		{
			tree_zip(prefix_tree->RChild);
		}
	}	
}
void build_prefix_zip_tree(Tree_zip prefix_tree) 
{
	prefix_tree->port = 255;
	prefix_tree->unzipable = 1;
	FILE *fp = fopen(source, "r");
	uint32_t ip_pointer = 1 << 31;
	TNode_zip *node = NULL;
	IP_entry *ip_entry = (IP_entry*)malloc(sizeof(IP_entry));
	char s[25];

	while (1)
	 {
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
		int i = 0;
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];
		node = prefix_tree;

		int IP_bit[32] = {0};
		for(i = 0; i < 32; i++)
		{
			IP_bit[i] = ip_entry->ip & (ip_pointer >> i);
			if(i >= ip_entry->mask)
			    IP_bit[i] = -1;
		}
		for (int j = 0; j < ip_entry->mask; j++) 
		{
			if (IP_bit[j]) {
				if (!node->RChild) 
				{
					TNode_zip *tmp_node = (TNode_zip*)malloc(sizeof(TNode_zip));
					tmp_node->LChild = tmp_node->RChild = NULL;
					tmp_node->Lnum = 0;
					tmp_node->L_mask = 0;
					tmp_node->Rnum = 0;
					tmp_node->R_mask = 0;
					tmp_node->unzipable = 0;
					tmp_node->port = node->port;
					node->RChild = tmp_node;
				}
				node = node->RChild;
			} 
			else 
			{
				if (!node->LChild) 
				{
					TNode_zip *tmp_node = (TNode_zip*)malloc(sizeof(TNode_zip));
					tmp_node->LChild = tmp_node->RChild = NULL;
					tmp_node->Lnum = 0;
					tmp_node->L_mask = 0;
					tmp_node->Rnum = 0;
					tmp_node->R_mask = 0;
					tmp_node->unzipable = 0;
					tmp_node->port = node->port;
					node->LChild = tmp_node;
				}
				node = node->LChild;
			}
		}
		node->port = ip_entry->port;
		node->unzipable = 1;
	}
	sign_zipable(prefix_tree);
	tree_zip(prefix_tree);
	fclose(fp);
}

uint32_t lookup_prefix_zip_tree(Tree_zip prefix_tree, uint32_t IP) 
{
	uint32_t ip_pointer = 1 << 31;
	TNode_zip *node = prefix_tree;
	TNode_zip *parent_node = NULL;
	int IP_bit[32] = {0};
	for(int i = 0; i < 32; i++)
		{
			IP_bit[i] = IP & (ip_pointer >> i);
		}
	for (int i = 0; node; i++) {
		parent_node = node;
		int flag = IP_bit[i] ? 1 : 0;
		node = IP_bit[i] ? node->RChild : node->LChild;
        int j = IP_bit[i] ? parent_node->Rnum : parent_node->Lnum;
		while(j > 0)
		{
			i++;
			int ip_i = IP_bit[i] ? 1 : 0 ;
			if( flag &(ip_i != ((parent_node->R_mask >> (j-1)) & 1) ))
			{
			    return parent_node->port;
			}
			if(!flag &(ip_i != ((parent_node->L_mask >> (j-1)) & 1) ))
			{
			    return parent_node->port;
			}
			j--;
			
		}
	}
	return parent_node->port;
}

void build_2bits_prefix_tree(Tree_2bits prefix_tree) 
{
	prefix_tree->port = 255;
	FILE *fp = fopen(source, "r");
	uint32_t ip_pointer = 1 << 31;
	Tnode_2bit *node = NULL;
	IP_entry *ip_entry = (IP_entry*)malloc(sizeof(IP_entry));
	char s[25];

	while (1)
	{
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
		int i = 0;
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];
		node = prefix_tree;

		int IP_bit[32] = {0};
		for(i = 0; i < 32; i++)
		{
			IP_bit[i] = ip_entry->ip & (ip_pointer >> i);
			if(i >= ip_entry->mask)
			    IP_bit[i] = -1;
		}

		for (int j = 0; j < ip_entry->mask-1; j += 2) 
		{
			if (IP_bit[j] ) 
			{
				if (IP_bit[j + 1]) 
				{
					if (!node->Child11) 
					{
						Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
						tmp_node->Child00 = tmp_node->Child01 = NULL;
	                    tmp_node->Child10 = tmp_node->Child11 = NULL;
	                    tmp_node->port = node->port;
						node->Child11 = tmp_node;
					}
					node = node->Child11;
				} 
				else 
				{
					if (!node->Child10) 
					{
						Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
						tmp_node->Child00 = tmp_node->Child01 = NULL;
	                    tmp_node->Child10 = tmp_node->Child11 = NULL;
	                    tmp_node->port = node->port;
						node->Child10 = tmp_node;
					}
					node = node->Child10;
				}
			} 
			else 
			{
				if (IP_bit[j + 1]) 
				{
					if (!node->Child01) 
					{
						Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
						tmp_node->Child00 = tmp_node->Child01 = NULL;
	                    tmp_node->Child10 = tmp_node->Child11 = NULL;
	                    tmp_node->port = node->port;
						node->Child01 = tmp_node;
					}
					node = node->Child01;
				} 
				else 
				{
					if (!node->Child00) 
					{
						Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
						tmp_node->Child00 = tmp_node->Child01 = NULL;
	                    tmp_node->Child10 = tmp_node->Child11 = NULL;
	                    tmp_node->port = node->port;
						node->Child00 = tmp_node;
					}
					node = node->Child00;
				}
			}
		} 
		if (ip_entry->mask % 2) 
		{
			if (IP_bit[ip_entry->mask-1]) 
			{
				if (!node->Child11) 
				{
					Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
					tmp_node->Child00 = tmp_node->Child01 = NULL;
	                tmp_node->Child10 = tmp_node->Child11 = NULL;
	                tmp_node->port = ip_entry->port;
					node->Child11 = tmp_node;
				}
				if (!node->Child10) 
				{
					Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
					tmp_node->Child00 = tmp_node->Child01 = NULL;
	                tmp_node->Child10 = tmp_node->Child11 = NULL;
	                tmp_node->port = ip_entry->port;
					node->Child10 = tmp_node;
				}
			} 
			else 
			{
				if (!node->Child01) 
				{
					Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
					tmp_node->Child00 = tmp_node->Child01 = NULL;
	                tmp_node->Child10 = tmp_node->Child11 = NULL;
	                tmp_node->port = ip_entry->port;
					node->Child01 = tmp_node;
				}
				if (!node->Child00) 
				{
					Tnode_2bit *tmp_node = (Tnode_2bit*)malloc(sizeof(Tnode_2bit));
					tmp_node->Child00 = tmp_node->Child01 = NULL;
	                tmp_node->Child10 = tmp_node->Child11 = NULL;
	                tmp_node->port = ip_entry->port;
					node->Child00 = tmp_node;
				}
			}
		} else {
			node->port = ip_entry->port;
		}
	}
	fclose(fp);
}

uint32_t lookup_prefix_tree(Tree prefix_tree, uint32_t IP) 
{
	uint32_t ip_pointer = 1 << 31;
	TNode *node = prefix_tree;
	TNode *parent_node = NULL;
	int IP_bit[32] = {0};
	for(int i = 0; i < 32; i++)
		{
			IP_bit[i] = IP & (ip_pointer >> i);
		}
	for (int i = 0; node; i++) {
		parent_node = node;
		node = IP_bit[i] ? node->RChild : node->LChild;
	}
	return parent_node->port;
}

uint32_t lookup_2bits_prefix_tree(Tree_2bits prefix_tree, uint32_t IP) 
{
	uint32_t ip_pointer = 1 << 31;
	Tnode_2bit *node = prefix_tree;
	Tnode_2bit *parent_node = NULL;

	int IP_bit[32] = {0};
		for(int i = 0; i < 32; i++)
		{
			IP_bit[i] = IP & (ip_pointer >> i);

		}

	for (int i = 0; node; i += 2) 
	{
		parent_node = node;
		if (IP_bit[i]) 
		{
			if(IP_bit[i + 1])
			    node = node->Child11;
			else node = node->Child10;
		} 
		else 
		{
			if(IP_bit[i + 1])
			    node = node->Child01;
			else node = node->Child00;
		}
	}
	return parent_node->port;
}

void total_nodes_for_1bits_tree(Tree prefix_tree, int* nodes) 
{
	if (prefix_tree->LChild) total_nodes_for_1bits_tree(prefix_tree->LChild, nodes);
	if (prefix_tree->RChild) total_nodes_for_1bits_tree(prefix_tree->RChild, nodes);
	*nodes = *nodes + 1;
}

void total_nodes_for_2bits_tree(Tree_2bits prefix_tree, int* nodes) 
{
	if(prefix_tree->Child00) total_nodes_for_2bits_tree(prefix_tree->Child00, nodes);
	if(prefix_tree->Child01) total_nodes_for_2bits_tree(prefix_tree->Child01, nodes);
	if(prefix_tree->Child10) total_nodes_for_2bits_tree(prefix_tree->Child10, nodes);
	if(prefix_tree->Child11) total_nodes_for_2bits_tree(prefix_tree->Child11, nodes);
	*nodes = *nodes + 1;
}

int main() 
{
	Tree prefix_tree_1bit = (Tree)malloc(sizeof(TNode));
	Tree_zip prefix_tree_1bit_zip = (Tree_zip)malloc(sizeof(TNode_zip));
	Tree_2bits prefix_tree_2bits = (Tree_2bits)malloc(sizeof(Tnode_2bit));
	int nodes = 0;

	build_prefix_tree(prefix_tree_1bit);
	total_nodes_for_1bits_tree(prefix_tree_1bit, &nodes);
	printf("For all IP in forwarding-table.txt:\n  ");
	printf("1_bit_prefix_tree:\n");
	printf("    %d nodes\n    %ld B.\n", nodes, sizeof(TNode) * nodes);

	//////////
	nodes = 0;
	build_prefix_zip_tree(prefix_tree_1bit_zip);
	total_nodes_for_1bits_tree(prefix_tree_1bit_zip, &nodes);
	printf("1_bit_prefix_zip_tree:\n");
	printf("    %d nodes\n    %ld B.\n", nodes, sizeof(TNode) * nodes);
    
	nodes = 0;
	build_2bits_prefix_tree(prefix_tree_2bits);
	total_nodes_for_2bits_tree(prefix_tree_2bits, &nodes);
	printf("2_bits_prefix_tree:\n");
	printf("    %d nodes\n    %ld B.\n", nodes, sizeof(Tnode_2bit) * nodes);

	FILE *fp = fopen(test, "r");
	IP_entry *ip_entry = (IP_entry*)malloc(sizeof(IP_entry));
	uint32_t res_port;
	char s[30];
	clock_t start, finish;
	start = clock();
	while (1) 
	{
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];

		res_port = lookup_prefix_tree(prefix_tree_1bit, ip_entry->ip);
		if (ip_entry->port != res_port) 
		{
			Error(res_port, ip_entry);
		}

	}
	finish = clock();
	printf("Search all IP in test-table.txt:\n  ");
	printf("1_bit_prefix_tree_search totally takes  %f seconds.\n  ", (double)(finish - start) / CLOCKS_PER_SEC);
	fclose(fp);

    //////////////////
	fp = fopen(test, "r");
	start = clock();
	while (1) 
	{
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];
		
		res_port = lookup_prefix_zip_tree(prefix_tree_1bit_zip, ip_entry->ip);
		if (ip_entry->port != res_port) 
		{
			Error(res_port, ip_entry);
		}

	}
	finish = clock();
	printf("1_bits_prefix_zip_tree_search totally takes  %f seconds.\n", (double)(finish - start) / CLOCKS_PER_SEC);
	fclose(fp);


    fp = fopen(test, "r");
	start = clock();
	while (1) 
	{
		fgets(s, 30, fp);
		if(feof(fp))
		{
			break;
		}
		memset(ip_entry, 0, sizeof(IP_entry));
		uint32_t IP[4] = {0};
        sscanf(s, "%u.%u.%u.%u %u %u", &IP[0], &IP[1], &IP[2], &IP[3], &ip_entry->mask, &ip_entry->port);
        ip_entry->ip = IP[0];
		ip_entry->ip = (ip_entry->ip << 8) + IP[1];
		ip_entry->ip = (ip_entry->ip << 8) + IP[2];
		ip_entry->ip = (ip_entry->ip << 8) + IP[3];
		
		res_port = lookup_2bits_prefix_tree(prefix_tree_2bits, ip_entry->ip);
		if (ip_entry->port != res_port) 
		{
			Error(res_port, ip_entry);
		}
	}
	finish = clock();
	printf("  2_bits_prefix_tree_search totally takes  %f seconds.\n", (double)(finish - start) / CLOCKS_PER_SEC);
	fclose(fp);
}
