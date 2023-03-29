// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include "bgp_aspa.h"

#define VALID 1
#define UNKNOWN 2
#define INVALID 3

#define UPSTREAM 0
#define DOWNSTREAM 1

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

static void *(*_malloc)(size_t) = NULL;
static void *(*_realloc)(void *, size_t) = NULL;
static void (*_free)(void *) = NULL;

// hashmap_set_allocator allows for configuring a custom allocator for
// all hashmap library operations. This function, if needed, should be called
// only once at startup and a prior to calling hashmap_new().
void hashmap_set_allocator(void *(*malloc)(size_t), void (*free)(void*)) 
{
    _malloc = malloc;
    _free = free;
}

#define panic(_msg_) { \
    fprintf(stderr, "panic: %s (%s:%d)\n", (_msg_), __FILE__, __LINE__); \
    exit(1); \
}

struct bucket {
    uint64_t hash:48;
    uint64_t dib:16;
};

// hashmap is an open addressed hash map using robinhood hashing.
// struct hashmap {
//     void *(*malloc)(size_t);
//     void *(*realloc)(void *, size_t);
//     void (*free)(void *);
//     bool oom;
//     size_t elsize;
//     size_t cap;
//     uint64_t seed0;
//     uint64_t seed1;
//     uint64_t (*hash)(const void *item, uint64_t seed0, uint64_t seed1);
//     int (*compare)(const void *a, const void *b, void *udata);
//     void (*elfree)(void *item);
//     void *udata;
//     size_t bucketsz;
//     size_t nbuckets;
//     size_t count;
//     size_t mask;
//     size_t growat;
//     size_t shrinkat;
//     void *buckets;
//     void *spare;
//     void *edata;
// };

static struct bucket *bucket_at(struct hashmap *map, size_t index) {
    return (struct bucket*)(((char*)map->buckets)+(map->bucketsz*index));
}

static void *bucket_item(struct bucket *entry) {
    return ((char*)entry)+sizeof(struct bucket);
}

static uint64_t get_hash(struct hashmap *map, const void *key) {
    return map->hash(key, map->seed0, map->seed1) << 16 >> 16;
}

// hashmap_new_with_allocator returns a new hash map using a custom allocator.
// See hashmap_new for more information information
struct hashmap *hashmap_new_with_allocator(
                            void *(*_malloc)(size_t), 
                            void *(*_realloc)(void*, size_t), 
                            void (*_free)(void*),
                            size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata)
{
    _malloc = _malloc ? _malloc : malloc;
    _realloc = _realloc ? _realloc : realloc;
    _free = _free ? _free : free;
    int ncap = 16;
    if (cap < ncap) {
        cap = ncap;
    } else {
        while (ncap < cap) {
            ncap *= 2;
        }
        cap = ncap;
    }
    size_t bucketsz = sizeof(struct bucket) + elsize;
    while (bucketsz & (sizeof(uintptr_t)-1)) {
        bucketsz++;
    }
    // hashmap + spare + edata
    size_t size = sizeof(struct hashmap)+bucketsz*2;
    struct hashmap *map = _malloc(size);
    if (!map) {
        return NULL;
    }
    memset(map, 0, sizeof(struct hashmap));
    map->elsize = elsize;
    map->bucketsz = bucketsz;
    map->seed0 = seed0;
    map->seed1 = seed1;
    map->hash = hash;
    map->compare = compare;
    map->elfree = elfree;
    map->udata = udata;
    map->spare = ((char*)map)+sizeof(struct hashmap);
    map->edata = (char*)map->spare+bucketsz;
    map->cap = cap;
    map->nbuckets = cap;
    map->mask = map->nbuckets-1;
    map->buckets = _malloc(map->bucketsz*map->nbuckets);
    if (!map->buckets) {
        _free(map);
        return NULL;
    }
    memset(map->buckets, 0, map->bucketsz*map->nbuckets);
    map->growat = map->nbuckets*0.75;
    map->shrinkat = map->nbuckets*0.10;
    map->malloc = _malloc;
    map->realloc = _realloc;
    map->free = _free;
    return map;  
}


// hashmap_new returns a new hash map. 
// Param `elsize` is the size of each element in the tree. Every element that
// is inserted, deleted, or retrieved will be this size.
// Param `cap` is the default lower capacity of the hashmap. Setting this to
// zero will default to 16.
// Params `seed0` and `seed1` are optional seed values that are passed to the 
// following `hash` function. These can be any value you wish but it's often 
// best to use randomly generated values.
// Param `hash` is a function that generates a hash value for an item. It's
// important that you provide a good hash function, otherwise it will perform
// poorly or be vulnerable to Denial-of-service attacks. This implementation
// comes with two helper functions `hashmap_sip()` and `hashmap_murmur()`.
// Param `compare` is a function that compares items in the tree. See the 
// qsort stdlib function for an example of how this function works.
// The hashmap must be freed with hashmap_free(). 
// Param `elfree` is a function that frees a specific item. This should be NULL
// unless you're storing some kind of reference data in the hash.
struct hashmap *hashmap_new(size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void (*elfree)(void *item),
                            void *udata)
{
    return hashmap_new_with_allocator(
        (_malloc?_malloc:malloc),
        (_realloc?_realloc:realloc),
        (_free?_free:free),
        elsize, cap, seed0, seed1, hash, compare, elfree, udata
    );
}

static void free_elements(struct hashmap *map) {
    if (map->elfree) {
        for (size_t i = 0; i < map->nbuckets; i++) {
            struct bucket *bucket = bucket_at(map, i);
            if (bucket->dib) map->elfree(bucket_item(bucket));
        }
    }
}


// hashmap_clear quickly clears the map. 
// Every item is called with the element-freeing function given in hashmap_new,
// if present, to free any data referenced in the elements of the hashmap.
// When the update_cap is provided, the map's capacity will be updated to match
// the currently number of allocated buckets. This is an optimization to ensure
// that this operation does not perform any allocations.
void hashmap_clear(struct hashmap *map, bool update_cap) {
    map->count = 0;
    free_elements(map);
    if (update_cap) {
        map->cap = map->nbuckets;
    } else if (map->nbuckets != map->cap) {
        void *new_buckets = map->malloc(map->bucketsz*map->cap);
        if (new_buckets) {
            map->free(map->buckets);
            map->buckets = new_buckets;
        }
        map->nbuckets = map->cap;
    }
    memset(map->buckets, 0, map->bucketsz*map->nbuckets);
    map->mask = map->nbuckets-1;
    map->growat = map->nbuckets*0.75;
    map->shrinkat = map->nbuckets*0.10;
}


static bool resize(struct hashmap *map, size_t new_cap) {
    struct hashmap *map2 = hashmap_new_with_allocator(map->malloc, map->realloc, map->free,
                                                      map->elsize, new_cap, map->seed0, 
                                                      map->seed1, map->hash, map->compare,
                                                      map->elfree, map->udata);
    if (!map2) {
        return false;
    }
    for (size_t i = 0; i < map->nbuckets; i++) {
        struct bucket *entry = bucket_at(map, i);
        if (!entry->dib) {
            continue;
        }
        entry->dib = 1;
        size_t j = entry->hash & map2->mask;
        for (;;) {
            struct bucket *bucket = bucket_at(map2, j);
            if (bucket->dib == 0) {
                memcpy(bucket, entry, map->bucketsz);
                break;
            }
            if (bucket->dib < entry->dib) {
                memcpy(map2->spare, bucket, map->bucketsz);
                memcpy(bucket, entry, map->bucketsz);
                memcpy(entry, map2->spare, map->bucketsz);
            }
            j = (j + 1) & map2->mask;
            entry->dib += 1;
        }
	}
    map->free(map->buckets);
    map->buckets = map2->buckets;
    map->nbuckets = map2->nbuckets;
    map->mask = map2->mask;
    map->growat = map2->growat;
    map->shrinkat = map2->shrinkat;
    map->free(map2);
    return true;
}

// hashmap_set inserts or replaces an item in the hash map. If an item is
// replaced then it is returned otherwise NULL is returned. This operation
// may allocate memory. If the system is unable to allocate additional
// memory then NULL is returned and hashmap_oom() returns true.
void *hashmap_set(struct hashmap *map, const void *item) {
    if (!item) {
        panic("item is null");
    }
    map->oom = false;
    if (map->count == map->growat) {
        if (!resize(map, map->nbuckets*2)) {
            map->oom = true;
            return NULL;
        }
    }

    
    struct bucket *entry = map->edata;
    entry->hash = get_hash(map, item);
    entry->dib = 1;
    memcpy(bucket_item(entry), item, map->elsize);
    
    size_t i = entry->hash & map->mask;
	for (;;) {
        struct bucket *bucket = bucket_at(map, i);
        if (bucket->dib == 0) {
            memcpy(bucket, entry, map->bucketsz);
            map->count++;
			return NULL;
		}
        if (entry->hash == bucket->hash && 
            map->compare(bucket_item(entry), bucket_item(bucket), 
                         map->udata) == 0)
        {
            memcpy(map->spare, bucket_item(bucket), map->elsize);
            memcpy(bucket_item(bucket), bucket_item(entry), map->elsize);
            return map->spare;
		}
        if (bucket->dib < entry->dib) {
            memcpy(map->spare, bucket, map->bucketsz);
            memcpy(bucket, entry, map->bucketsz);
            memcpy(entry, map->spare, map->bucketsz);
		}
		i = (i + 1) & map->mask;
        entry->dib += 1;
	}
}

// hashmap_get returns the item based on the provided key. If the item is not
// found then NULL is returned.
void *hashmap_get(struct hashmap *map, const void *key) {
    if (!key) {
        panic("key is null");
    }
    uint64_t hash = get_hash(map, key);
	size_t i = hash & map->mask;
	for (;;) {
        struct bucket *bucket = bucket_at(map, i);
		if (!bucket->dib) {
			return NULL;
		}
		if (bucket->hash == hash && 
            map->compare(key, bucket_item(bucket), map->udata) == 0)
        {
            return bucket_item(bucket);
		}
		i = (i + 1) & map->mask;
	}
}

// hashmap_probe returns the item in the bucket at position or NULL if an item
// is not set for that bucket. The position is 'moduloed' by the number of 
// buckets in the hashmap.
void *hashmap_probe(struct hashmap *map, uint64_t position) {
    size_t i = position & map->mask;
    struct bucket *bucket = bucket_at(map, i);
    if (!bucket->dib) {
		return NULL;
	}
    return bucket_item(bucket);
}


// hashmap_delete removes an item from the hash map and returns it. If the
// item is not found then NULL is returned.
void *hashmap_delete(struct hashmap *map, void *key) {
    if (!key) {
        panic("key is null");
    }
    map->oom = false;
    uint64_t hash = get_hash(map, key);
	size_t i = hash & map->mask;
	for (;;) {
        struct bucket *bucket = bucket_at(map, i);
		if (!bucket->dib) {
			return NULL;
		}
		if (bucket->hash == hash && 
            map->compare(key, bucket_item(bucket), map->udata) == 0)
        {
            memcpy(map->spare, bucket_item(bucket), map->elsize);
            bucket->dib = 0;
            for (;;) {
                struct bucket *prev = bucket;
                i = (i + 1) & map->mask;
                bucket = bucket_at(map, i);
                if (bucket->dib <= 1) {
                    prev->dib = 0;
                    break;
                }
                memcpy(prev, bucket, map->bucketsz);
                prev->dib--;
            }
            map->count--;
            if (map->nbuckets > map->cap && map->count <= map->shrinkat) {
                // Ignore the return value. It's ok for the resize operation to
                // fail to allocate enough memory because a shrink operation
                // does not change the integrity of the data.
                resize(map, map->nbuckets/2);
            }
			return map->spare;
		}
		i = (i + 1) & map->mask;
	}
}

// hashmap_count returns the number of items in the hash map.
size_t hashmap_count(struct hashmap *map) {
    return map->count;
}

// hashmap_free frees the hash map
// Every item is called with the element-freeing function given in hashmap_new,
// if present, to free any data referenced in the elements of the hashmap.
void hashmap_free(struct hashmap *map) {
    if (!map) return;
    free_elements(map);
    map->free(map->buckets);
    map->free(map);
}

// hashmap_oom returns true if the last hashmap_set() call failed due to the 
// system being out of memory.
bool hashmap_oom(struct hashmap *map) {
    return map->oom;
}

// hashmap_scan iterates over all items in the hash map
// Param `iter` can return false to stop iteration early.
// Returns false if the iteration has been stopped early.
bool hashmap_scan(struct hashmap *map, 
                  bool (*iter)(const void *item, void *udata), void *udata)
{
    for (size_t i = 0; i < map->nbuckets; i++) {
        struct bucket *bucket = bucket_at(map, i);
        if (bucket->dib) {
            if (!iter(bucket_item(bucket), udata)) {
                return false;
            }
        }
    }
    return true;
}


// hashmap_iter iterates one key at a time yielding a reference to an
// entry at each iteration. Useful to write simple loops and avoid writing
// dedicated callbacks and udata structures, as in hashmap_scan.
//
// map is a hash map handle. i is a pointer to a size_t cursor that
// should be initialized to 0 at the beginning of the loop. item is a void
// pointer pointer that is populated with the retrieved item. Note that this
// is NOT a copy of the item stored in the hash map and can be directly
// modified.
//
// Note that if hashmap_delete() is called on the hashmap being iterated,
// the buckets are rearranged and the iterator must be reset to 0, otherwise
// unexpected results may be returned after deletion.
//
// This function has not been tested for thread safety.
//
// The function returns true if an item was retrieved; false if the end of the
// iteration has been reached.
bool hashmap_iter(struct hashmap *map, size_t *i, void **item)
{
    struct bucket *bucket;

    do {
        if (*i >= map->nbuckets) return false;

        bucket = bucket_at(map, *i);
        (*i)++;
    } while (!bucket->dib);

    *item = bucket_item(bucket);

    return true;
}


//-----------------------------------------------------------------------------
// SipHash reference C implementation
//
// Copyright (c) 2012-2016 Jean-Philippe Aumasson
// <jeanphilippe.aumasson@gmail.com>
// Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software. If not, see
// <http://creativecommons.org/publicdomain/zero/1.0/>.
//
// default: SipHash-2-4
//-----------------------------------------------------------------------------
static uint64_t SIP64(const uint8_t *in, const size_t inlen, 
                      uint64_t seed0, uint64_t seed1) 
{
#define U8TO64_LE(p) \
    {  (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) | \
        ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) | \
        ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) | \
        ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56)) }
#define U64TO8_LE(p, v) \
    { U32TO8_LE((p), (uint32_t)((v))); \
      U32TO8_LE((p) + 4, (uint32_t)((v) >> 32)); }
#define U32TO8_LE(p, v) \
    { (p)[0] = (uint8_t)((v)); \
      (p)[1] = (uint8_t)((v) >> 8); \
      (p)[2] = (uint8_t)((v) >> 16); \
      (p)[3] = (uint8_t)((v) >> 24); }
#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND \
    { v0 += v1; v1 = ROTL(v1, 13); \
      v1 ^= v0; v0 = ROTL(v0, 32); \
      v2 += v3; v3 = ROTL(v3, 16); \
      v3 ^= v2; \
      v0 += v3; v3 = ROTL(v3, 21); \
      v3 ^= v0; \
      v2 += v1; v1 = ROTL(v1, 17); \
      v1 ^= v2; v2 = ROTL(v2, 32); }
    uint64_t k0 = U8TO64_LE((uint8_t*)&seed0);
    uint64_t k1 = U8TO64_LE((uint8_t*)&seed1);
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    const uint8_t *end = in + inlen - (inlen % sizeof(uint64_t));
    for (; in != end; in += 8) {
        uint64_t m = U8TO64_LE(in);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }
    const int left = inlen & 7;
    uint64_t b = ((uint64_t)inlen) << 56;
    switch (left) {
    case 7: b |= ((uint64_t)in[6]) << 48;
    case 6: b |= ((uint64_t)in[5]) << 40;
    case 5: b |= ((uint64_t)in[4]) << 32;
    case 4: b |= ((uint64_t)in[3]) << 24;
    case 3: b |= ((uint64_t)in[2]) << 16;
    case 2: b |= ((uint64_t)in[1]) << 8;
    case 1: b |= ((uint64_t)in[0]); break;
    case 0: break;
    }
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    b = v0 ^ v1 ^ v2 ^ v3;
    uint64_t out = 0;
    U64TO8_LE((uint8_t*)&out, b);
    return out;
}

//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.
//
// Murmur3_86_128
//-----------------------------------------------------------------------------
static void MM86128(const void *key, const int len, uint32_t seed, void *out) {
#define	ROTL32(x, r) ((x << r) | (x >> (32 - r)))
#define FMIX32(h) h^=h>>16; h*=0x85ebca6b; h^=h>>13; h*=0xc2b2ae35; h^=h>>16;
    const uint8_t * data = (const uint8_t*)key;
    const int nblocks = len / 16;
    uint32_t h1 = seed;
    uint32_t h2 = seed;
    uint32_t h3 = seed;
    uint32_t h4 = seed;
    uint32_t c1 = 0x239b961b; 
    uint32_t c2 = 0xab0e9789;
    uint32_t c3 = 0x38b34ae5; 
    uint32_t c4 = 0xa1e38b93;
    const uint32_t * blocks = (const uint32_t *)(data + nblocks*16);
    for (int i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i*4+0];
        uint32_t k2 = blocks[i*4+1];
        uint32_t k3 = blocks[i*4+2];
        uint32_t k4 = blocks[i*4+3];
        k1 *= c1; k1  = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
        h1 = ROTL32(h1,19); h1 += h2; h1 = h1*5+0x561ccd1b;
        k2 *= c2; k2  = ROTL32(k2,16); k2 *= c3; h2 ^= k2;
        h2 = ROTL32(h2,17); h2 += h3; h2 = h2*5+0x0bcaa747;
        k3 *= c3; k3  = ROTL32(k3,17); k3 *= c4; h3 ^= k3;
        h3 = ROTL32(h3,15); h3 += h4; h3 = h3*5+0x96cd1c35;
        k4 *= c4; k4  = ROTL32(k4,18); k4 *= c1; h4 ^= k4;
        h4 = ROTL32(h4,13); h4 += h1; h4 = h4*5+0x32ac3b17;
    }
    const uint8_t * tail = (const uint8_t*)(data + nblocks*16);
    uint32_t k1 = 0;
    uint32_t k2 = 0;
    uint32_t k3 = 0;
    uint32_t k4 = 0;
    switch(len & 15) {
    case 15: k4 ^= tail[14] << 16;
    case 14: k4 ^= tail[13] << 8;
    case 13: k4 ^= tail[12] << 0;
             k4 *= c4; k4  = ROTL32(k4,18); k4 *= c1; h4 ^= k4;
    case 12: k3 ^= tail[11] << 24;
    case 11: k3 ^= tail[10] << 16;
    case 10: k3 ^= tail[ 9] << 8;
    case  9: k3 ^= tail[ 8] << 0;
             k3 *= c3; k3  = ROTL32(k3,17); k3 *= c4; h3 ^= k3;
    case  8: k2 ^= tail[ 7] << 24;
    case  7: k2 ^= tail[ 6] << 16;
    case  6: k2 ^= tail[ 5] << 8;
    case  5: k2 ^= tail[ 4] << 0;
             k2 *= c2; k2  = ROTL32(k2,16); k2 *= c3; h2 ^= k2;
    case  4: k1 ^= tail[ 3] << 24;
    case  3: k1 ^= tail[ 2] << 16;
    case  2: k1 ^= tail[ 1] << 8;
    case  1: k1 ^= tail[ 0] << 0;
             k1 *= c1; k1  = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
    };
    h1 ^= len; h2 ^= len; h3 ^= len; h4 ^= len;
    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;
    FMIX32(h1); FMIX32(h2); FMIX32(h3); FMIX32(h4);
    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;
    ((uint32_t*)out)[0] = h1;
    ((uint32_t*)out)[1] = h2;
    ((uint32_t*)out)[2] = h3;
    ((uint32_t*)out)[3] = h4;
}

// hashmap_sip returns a hash value for `data` using SipHash-2-4.
uint64_t hashmap_sip(const void *data, size_t len, 
                     uint64_t seed0, uint64_t seed1)
{
    return SIP64((uint8_t*)data, len, seed0, seed1);
}

// hashmap_murmur returns a hash value for `data` using Murmur3_86_128.
uint64_t hashmap_murmur(const void *data, size_t len, 
                        uint64_t seed0, uint64_t seed1)
{
    char out[16];
    MM86128(data, len, seed0, &out);
    return *(uint64_t*)out;
}

// struct provider
// {
//     uint32_t AS;
//     uint32_t len;
//     uint32_t *providers;
// };

int provider_compare(const void *a, const void *b, void *pdata)
{
    const struct provider *pa = a;
    const struct provider *pb = b;
    printf("provider_compare ");
    printf("%d \n", pa->AS > pb->AS);
    return (pa->AS > pb->AS);
}

uint64_t provider_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct provider *p = item;
    char a[10];
    sprintf(a, "%d", p->AS);
    //printf("asnum: %s, hash key: %ld\n", a, hashmap_sip(a, strlen(a), seed0, seed1));
    return hashmap_sip(a, strlen(a), seed0, seed1);
}

#define conf_file_name "/home/frr/hrov_conf.txt"
char *bgpdump_name;
static int check_key(char *line, char *key)
{
    char *k_start, *k_end;// 指示 key 在 line 中的起始和结束位置
    int line_len;
    line_len = strlen(line);
    if(line_len < 3)
        return(-1);
    else
    {
        k_start = &line[0];
        while(((*k_start == ' ') || (*k_start == '\t'))&& ( k_start <= &line[line_len - 1]))
            k_start ++;
        if(*k_start == '#')
            return -1;
        k_end = strchr(line, '=');
        if(k_end == NULL)
            return -1;
        k_end --;
        while(((*k_end == ' ') || (*k_end == '\t'))&& (k_end >= k_start))
            k_end --;
        if((*k_end == ' ') || (*k_end == '\t'))
            return -1;
        if(strncmp(key, k_start, k_end-k_start + 1) != 0)
            return -1;
    }
    return 0 ;
}

static char* get_value(char *line)
{
    char *v_start, *v_end;// 指示 value 在 line 中的起始和结束位置
    char *value = NULL;
    int line_len;
    int val_len;
    line_len = strlen(line);
    v_start = strchr(line, '=');// 已经在 check_key 中检验过'＝'的存在
    v_start ++;
    while(((*v_start == ' ') || (*v_start == '\t'))&& (v_start <= &line[line_len - 1]))
        v_start ++;
    v_end = &line[line_len - 1];
    if(((*v_end == ' ') || (*v_end == '\t')|| (*v_end == '\n')|| (*v_end == '\r'))&& (v_end > v_start))
        v_end --;
    if((*v_end == ' ') || (*v_end == '\t')|| (*v_end == '\n')|| (*v_end == '\r'))
        return NULL;
    val_len = v_end - v_start + 1;
    value = (char *)malloc((val_len + 1) * sizeof(char));
    if(value == NULL)
    {
        printf("malloc failed.\n");
        return NULL;
    }
    strncpy(value, v_start, val_len);
    value[val_len] = '\0';
    return value;
}/* get_value() */

char *read_config(FILE *fp, char *key)
{
    char line[300] = {'\0'};
    char *value = NULL;
    int ret;
    while(fgets( line, sizeof(line), fp) != NULL)
    {
        ret = check_key(line, key);
        if(ret == -1)
            continue;
        else
        {
            value = get_value(line);
            if(value == NULL)
            {
                return NULL;
            }
            else
                return value;
        }
    }/* while */
    return NULL;
}
int rpki_cof_read(char *filename)
{
	FILE *fp = fopen(filename, "rw");
	bgpdump_name = read_config(fp, "bgpdump_name");

	char buf[1024];
	int fp1 = -1;
	fp1 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	sprintf(buf, "%s \n", bgpdump_name);
	int write_n = write(fp1, buf, strlen(buf));
	close(fp1);

	close(fp);
    return 0;
}


struct hashmap *provider_map;

int aspa_init()
{

    provider_map = hashmap_new(sizeof(struct provider), 0, 0, 0, 
                                     provider_hash, provider_compare, NULL, NULL);

    char szTest[1000] = {0};
    FILE *fp = fopen("/home/frr/test/input.txt", "r");
    if(NULL == fp)
    {
        printf("failed to open dos.txt\n");
    }

    char buf[1024];
	int fp1 = -1;
	fp1 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	sprintf(buf, "aspa_init\n");
	int write_n = write(fp1, buf, strlen(buf));
	close(fp1);

    while(!feof(fp))
    {
        fgets(szTest, sizeof(szTest) - 1, fp); // 包含了换行符
        if(szTest[strlen(szTest)-1] == '\n')
            szTest[strlen(szTest)-1] = '\0';
        char *asnum_str = strtok(szTest, " ");
        char *cnt_str = strtok(NULL, " ");
        uint32_t asnum = atoi(asnum_str);
        uint32_t count = atoi(cnt_str);
        struct provider p;
        p.AS = asnum;
        p.len = count;
        p.providers = malloc(sizeof(uint32_t) * count);

        for(int i = 0; i < count; i++)
        {
            char *prov = strtok(NULL, " ");
            int p_as = atoi(prov);
            memcpy(p.providers+i, &p_as, sizeof(int));
        }
        hashmap_set(provider_map, &p);
    }
    fclose(fp);

    // struct provider *p;
    // p = hashmap_get(provider_map, &(struct provider){ .AS = 1212});

	// if(p)
	// {
	// 	char buf1[1024];
	// 	int fp11 = -1;
	// 	fp11 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	// 	sprintf(buf1, "asnum: %d, count: %d, path: %d\n", p->AS, p->len, p->providers[0]);
	// 	int write_n1 = write(fp11, buf1, strlen(buf1));
	// 	close(fp11);
	// }
	

    // p = hashmap_get(provider_map, &(struct provider){ .AS = 2});
	// if(p)
	// {
	// 	char buf1[1024];
	// 	int fp11 = -1;
	// 	fp11 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	// 	sprintf(buf1, "asnum: %d, count: %d, path: %d\n", p->AS, p->len, p->providers[0]);
	// 	int write_n1 = write(fp11, buf1, strlen(buf1));
	// 	close(fp11);
	// }
	// if(!p)
	// {
	// 	char buf1[1024];
	// 	int fp11 = -1;
	// 	fp11 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	// 	sprintf(buf1, "not exsit !!!!!!!!!!! \n");
	// 	int write_n1 = write(fp11, buf1, strlen(buf1));
	// 	close(fp11);
	// }

    return 1;
}

// int aspa_validate(char *as_path_str, int path_len, struct hashmap *hashmap_p, int type)
// {   

//     char buf[1024];
// 	int fp1 = -1;
// 	fp1 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
// 	sprintf(buf, "as_path_str: %s\n", as_path_str);
// 	int write_n = write(fp1, buf, strlen(buf));
// 	close(fp1);

//     struct provider *p;
//     p = hashmap_get(provider_map, &(struct provider){ .AS = 1212});

// 	if(p)
// 	{
// 		char buf1[1024];
// 		int fp11 = -1;
// 		fp11 = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
// 		sprintf(buf1, "asnum: %d, count: %d, path: %d, path_len: %d\n", p->AS, p->len, p->providers[0], path_len);
// 		int write_n1 = write(fp11, buf1, strlen(buf1));
// 		close(fp11);
// 	}

//     return 1;
// }

int cp_verification(uint32_t customer, uint32_t provider, struct hashmap *hashmap_p)
{

    // verification relation between customer and provider
    // return VAILD, UNKNOWN or INVALID

    struct provider *p = hashmap_get(hashmap_p, &(struct provider){.AS = customer});

    if (!p)
    {
        return UNKNOWN;
    }
    uint32_t *p_list = p->providers;
    // printf("addr : %p\n", (void *)p_list);

    for (int i = 0; i < p->len; i++)
    {
        // printf("AS %d provider : %d\n", p->AS, p_list[i]);
        if (p_list[i] == provider)
        {
            return VALID;
        }
    }
    return INVALID;
}

int upstream_paths_verification(uint32_t *as_path, int as_path_length, struct hashmap *hashmap_p)
{

    // ASPA verfication for upstream path(e.g. UPDATE is received from a customer or a lateral peer,
    // or by an RS-client at an IX RS.)
    // return VAILD, UNKNOWN or INVALID

    if (as_path_length <= 1)
        return VALID;

    int invalid_pair_index = as_path_length;
    int unknown_pair_index = as_path_length;

    for (int i = 0; i < as_path_length - 1; i++)
    {
        uint32_t customer = as_path[i];
        uint32_t provider = as_path[i + 1];
        int res = cp_verification(customer, provider, hashmap_p);
        if (res == INVALID)
        {
            invalid_pair_index = min(i + 1, invalid_pair_index);
        }
        else if (res == UNKNOWN)
        {
            unknown_pair_index = min(i + 1, unknown_pair_index);
        }
    }

    unknown_pair_index = min(unknown_pair_index, invalid_pair_index);

    // printf("%d\n", unknown_pair_index);
    // printf("%d\n", invalid_pair_index);

    if (invalid_pair_index < as_path_length)
    {
        return INVALID;
    }

    if (unknown_pair_index < as_path_length)
    {
        return UNKNOWN;
    }

    return VALID;
}

int downstream_paths_verification(uint32_t *as_path, int as_path_length, struct hashmap *hashmap_p)
{

    // ASPA verfication for downstream path(e.g. UPDATE is received from a provider)
    // return VAILD, UNKNOWN or INVALID

    if (as_path_length <= 1)
        return VALID;

    int invalid_pair_index = as_path_length;
    int unknown_pair_index = as_path_length;
    int reverse_invalid_pair_index = as_path_length;
    int reverse_unknown_pair_index = as_path_length;

    for (int i = 0; i < as_path_length - 1; i++)
    {
        uint32_t customer = as_path[i];
        uint32_t provider = as_path[i + 1];
        int res = cp_verification(customer, provider, hashmap_p);
        if (res == INVALID)
        {
            invalid_pair_index = min(i + 1, invalid_pair_index);
        }
        else if (res == UNKNOWN)
        {
            unknown_pair_index = min(i + 1, unknown_pair_index);
        }
    }

    unknown_pair_index = min(unknown_pair_index, invalid_pair_index);

    for (int i = as_path_length - 1; i > 0; i--)
    {
        uint32_t customer = as_path[i];
        uint32_t provider = as_path[i - 1];
        int res = cp_verification(customer, provider, hashmap_p);
        if (res == INVALID)
        {
            reverse_invalid_pair_index = min(
                as_path_length - i, reverse_invalid_pair_index);
        }
        else if (res == UNKNOWN)
        {
            reverse_unknown_pair_index = min(
                as_path_length - i, reverse_unknown_pair_index);
        }
    }

    reverse_unknown_pair_index = min(
        reverse_unknown_pair_index, reverse_invalid_pair_index);

    if (invalid_pair_index + reverse_invalid_pair_index < as_path_length)
    {
        return INVALID;
    }
    if (unknown_pair_index + reverse_unknown_pair_index < as_path_length)
    {
        return UNKNOWN;
    }

    return VALID;
}

int aspa_validate(char *as_path_str, int len, struct hashmap *hashmap_p, int type)
{
    uint32_t *reverse_path = (uint32_t *)malloc(sizeof(uint32_t) * len);
    char *start_ptr = as_path_str;
    char *now_ptr;
    for (int i = 0; i < len; i++)
    {
        reverse_path[len - i - 1] = strtol(start_ptr, &now_ptr, 10);
        start_ptr = now_ptr;
        now_ptr = NULL;
    }

    if (type == UPSTREAM)
    {
        return upstream_paths_verification(reverse_path, len, hashmap_p);
    }
    else if (type == DOWNSTREAM)
    {
        return downstream_paths_verification(reverse_path, len, hashmap_p);
    }
}

extern int aspa_test(int a)
{

    int a1 = aspa_validate("174 400043 23338", 3, provider_map, UPSTREAM);
    int b1 = aspa_validate("3356 3 174 400043 23338", 3, provider_map, DOWNSTREAM);

    char buf[1024];
	int fp = -1;
	fp = open("/home/frr/test/test.txt", O_RDWR|O_APPEND);
	sprintf(buf, "!!!!!!!!! resule1: %d, result2: %d\n", a1, b1);
	int write_n = write(fp, buf, strlen(buf));
	close(fp);
}