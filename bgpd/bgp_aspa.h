// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct hashmap {
    void *(*malloc)(size_t);
    void *(*realloc)(void *, size_t);
    void (*free)(void *);
    bool oom;
    size_t elsize;
    size_t cap;
    uint64_t seed0;
    uint64_t seed1;
    uint64_t (*hash)(const void *item, uint64_t seed0, uint64_t seed1);
    int (*compare)(const void *a, const void *b, void *udata);
    void (*elfree)(void *item);
    void *udata;
    size_t bucketsz;
    size_t nbuckets;
    size_t count;
    size_t mask;
    size_t growat;
    size_t shrinkat;
    void *buckets;
    void *spare;
    void *edata;
};
struct provider
{
    uint32_t AS;
    uint32_t len;
    uint32_t *providers;
};

extern struct hashmap *provider_map;

extern struct hashmap *hashmap_new(size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata);
extern struct hashmap *hashmap_new_with_allocator(
                            void *(*malloc)(size_t), 
                            void *(*realloc)(void *, size_t), 
                            void (*free)(void*),
                            size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata);
extern void hashmap_free(struct hashmap *map);
extern void hashmap_clear(struct hashmap *map, bool update_cap);
extern size_t hashmap_count(struct hashmap *map);
extern bool hashmap_oom(struct hashmap *map);
extern void *hashmap_get(struct hashmap *map, const void *item);
extern void *hashmap_set(struct hashmap *map, const void *item);
extern void *hashmap_delete(struct hashmap *map, void *item);
extern void *hashmap_probe(struct hashmap *map, uint64_t position);
extern bool hashmap_scan(struct hashmap *map,
                  bool (*iter)(const void *item, void *udata), void *udata);
extern bool hashmap_iter(struct hashmap *map, size_t *i, void **item);

extern uint64_t hashmap_sip(const void *data, size_t len, 
                     uint64_t seed0, uint64_t seed1);
extern uint64_t hashmap_murmur(const void *data, size_t len, 
                        uint64_t seed0, uint64_t seed1);


// DEPRECATED: use `hashmap_new_with_allocator`
extern void hashmap_set_allocator(void *(*malloc)(size_t), void (*free)(void*));
extern int aspa_init();
extern int aspa_test(int);
extern int aspa_validate(char *as_path_str, int path_len, struct hashmap *hashmap_p, int type);
