/* Fuzz ksurface's pid radix tree (Surface/libkern/radix/radix.c) — the process table every
 * proc_* syscall looks pids up in. The input is an op stream: [op:1][ident:8] records.
 * A plain array model mirrors the tree; any disagreement between lookup/remove/walk and the
 * model aborts (a functional bug), memory errors are caught by ASan. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>

#define MAX_KEYS 128

typedef struct { uint64_t ident; uintptr_t value; } entry_t;
typedef struct { entry_t e[MAX_KEYS]; size_t n; } model_t;
typedef struct { model_t *m; size_t seen; } walk_ctx_t;

static entry_t *model_find(model_t *m, uint64_t ident)
{
    for(size_t i = 0; i < m->n; i++) if(m->e[i].ident == ident) return &m->e[i];
    return NULL;
}

static void walk_cb(uint64_t ident, void *value, void *ctx)
{
    walk_ctx_t *w = ctx;
    entry_t *e = model_find(w->m, ident);
    if(e == NULL || (void *)e->value != value) abort();
    w->seen++;
}

static void free_nodes(radix_node_t *node, int level)
{
    if(node == NULL) return;
    if(level < RADIX_LEVELS - 1)
        for(int i = 0; i < RADIX_SIZE; i++) free_nodes(node->slots[i], level + 1);
    free(node);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    radix_tree_t tree = { NULL };
    model_t m; m.n = 0;
    uintptr_t next_value = 1;

    while(size >= 9)
    {
        uint8_t op = data[0];
        uint64_t ident;
        memcpy(&ident, data + 1, 8);
        data += 9; size -= 9;
        /* small idents share tree paths like real pids do */
        if(op & 0x80) ident &= 0xffff;

        switch(op & 3)
        {
            case 0: { /* insert / replace */
                entry_t *e = model_find(&m, ident);
                if(e == NULL && m.n == MAX_KEYS) break;
                uintptr_t v = (next_value++) << 4;
                if(radix_insert(&tree, ident, (void *)v) != 0) break;
                if(e) e->value = v; else { m.e[m.n].ident = ident; m.e[m.n].value = v; m.n++; }
                break;
            }
            case 1: { /* lookup */
                entry_t *e = model_find(&m, ident);
                void *got = radix_lookup(&tree, ident);
                if(got != (e ? (void *)e->value : NULL)) abort();
                break;
            }
            case 2: { /* remove */
                entry_t *e = model_find(&m, ident);
                void *got = radix_remove(&tree, ident);
                if(got != (e ? (void *)e->value : NULL)) abort();
                if(e) *e = m.e[--m.n];
                break;
            }
            case 3: { /* walk */
                walk_ctx_t w = { &m, 0 };
                radix_walk(&tree, walk_cb, &w);
                if(w.seen != m.n) abort();
                break;
            }
        }
    }
    free_nodes(tree.root, 0);
    return 0;
}
