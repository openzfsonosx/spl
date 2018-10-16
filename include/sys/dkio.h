
#ifndef _SPL_DKIO_H
#define	_SPL_DKIO_H

struct dk_callback {
	void (*dkc_callback)(void *dkc_cookie, int error);
	void *dkc_cookie;
	int dkc_flag;
};

#define	DKIOC			(0x04 << 8)
#define	DKIOCFLUSHWRITECACHE	(DKIOC | 34)
#define	DKIOCTRIM		(DKIOC | 35)

/*
 * ioctl to free space (e.g. SCSI UNMAP) off a disk.
 * Pass a dkioc_free_list_t containing a list of extents to be freed.
 */
#define DKIOCFREE       (DKIOC|50)

#define DF_WAIT_SYNC    0x00000001      /* Wait for full write-out of free. */
typedef struct dkioc_free_list_ext_s {
        uint64_t                dfle_start;
        uint64_t                dfle_length;
} dkioc_free_list_ext_t;

typedef struct dkioc_free_list_s {
        uint64_t                dfl_flags;
        uint64_t                dfl_num_exts;
        uint64_t                dfl_offset;
        dkioc_free_list_ext_t   dfl_exts[1];
} dkioc_free_list_t;
#define DFL_SZ(num_exts) \
        (sizeof (dkioc_free_list_t) + \
        (num_exts - 1) * sizeof (dkioc_free_list_ext_t))

/* Frees a variable-length dkioc_free_list_t structure. */
static inline void
dfl_free(dkioc_free_list_t *dfl)
{
	kmem_free(dfl, DFL_SZ(dfl->dfl_num_exts));
}

#endif /* _SPL_DKIO_H */
