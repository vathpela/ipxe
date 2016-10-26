/*
 * Copyright 2016 Peter Jones <pjones@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * Linux EFI Stub image format
 *
 */

#include <stdlib.h>
#include <bzimage.h>
#include <errno.h>
#include <initrd.h>
#include <ipxe/cpio.h>
#include <ipxe/efi/efi.h>
#include <include/ipxe/efi/IndustryStandard/PeImage.h>
#include <ipxe/image.h>
#include <ipxe/features.h>
#include <ipxe/init.h>

FEATURE ( FEATURE_IMAGE, "EFISTUB", DHCP_EB_FEATURE_EFISTUB, 1 );

typedef void (*handover_func) ( EFI_HANDLE , EFI_SYSTEM_TABLE *, void * );

struct le_context {
	struct image *image;
	struct bzimage_header *bzhdr;
	struct linux_kernel_params *params;
	userptr_t kernel_addr;
	size_t kernel_size;
};

/**
 * Parse standalone image command line for cpio parameters
 *
 * @v image		Linux EFI Stub file
 * @v cpio		CPIO header
 * @v cmdline		Command line
 */
static void leimage_parse_cpio_cmdline ( struct image *image,
					 struct cpio_header *cpio,
					 const char *cmdline ) {
	char *arg;
	char *end;
	unsigned int mode;

	/* Look for "mode=" */
	if ( ( arg = strstr ( cmdline, "mode=" ) ) ) {
		arg += 5;
		mode = strtoul ( arg, &end, 8 /* Octal for file mode */ );
		if ( *end && ( *end != ' ' ) ) {
			DBGC ( image, "efistub %p strange \"mode=\""
			       "terminator '%c'\n", image, *end );
		}
		cpio_set_field ( cpio->c_mode, ( 0100000 | mode ) );
	}
}


/**
 * Align initrd length
 *
 * @v len		Length
 * @ret len		Length rounded up to INITRD_ALIGN
 */
static inline size_t leimage_align ( size_t len ) {

	return ( ( len + INITRD_ALIGN - 1 ) & ~( INITRD_ALIGN - 1 ) );
}

/**
 * Load initrd
 *
 * @v image		efistub image
 * @v initrd		initrd image
 * @v address		Address at which to load, or UNULL
 * @ret len		Length of loaded image, excluding zero-padding
 */
static size_t leimage_load_initrd ( struct image *image,
				    struct image *initrd,
				    userptr_t address ) {
	char *filename = initrd->cmdline;
	char *cmdline;
	struct cpio_header cpio;
	size_t offset;
	size_t name_len;
	size_t pad_len;

	/* Do not include kernel image itself as an initrd */
	if ( initrd == image )
		return 0;

	/* Create cpio header for non-prebuilt images */
	if ( filename && filename[0] ) {
		cmdline = strchr ( filename, ' ' );
		name_len = ( ( cmdline ? ( ( size_t ) ( cmdline - filename ) )
			       : strlen ( filename ) ) + 1 /* NUL */ );
		memset ( &cpio, '0', sizeof ( cpio ) );
		memcpy ( cpio.c_magic, CPIO_MAGIC, sizeof ( cpio.c_magic ) );
		cpio_set_field ( cpio.c_mode, 0100644 );
		cpio_set_field ( cpio.c_nlink, 1 );
		cpio_set_field ( cpio.c_filesize, initrd->len );
		cpio_set_field ( cpio.c_namesize, name_len );
		if ( cmdline ) {
			leimage_parse_cpio_cmdline ( image, &cpio,
						     ( cmdline + 1 /* ' ' */ ));
		}
		offset = ( ( sizeof ( cpio ) + name_len + 0x03 ) & ~0x03 );
	} else {
		offset = 0;
		name_len = 0;
	}

	/* Copy in initrd image body (and cpio header if applicable) */
	if ( address ) {
		memmove_user ( address, offset, initrd->data, 0, initrd->len );
		if ( offset ) {
			memset_user ( address, 0, 0, offset );
			copy_to_user ( address, 0, &cpio, sizeof ( cpio ) );
			copy_to_user ( address, sizeof ( cpio ), filename,
				       ( name_len - 1 /* NUL (or space) */ ) );
		}
		DBGC ( image, "efistub %p initrd %p [%#08lx,%#08lx,%#08lx)"
		       "%s%s\n", image, initrd, user_to_phys ( address, 0 ),
		       user_to_phys ( address, offset ),
		       user_to_phys ( address, ( offset + initrd->len ) ),
		       ( filename ? " " : "" ), ( filename ? filename : "" ) );
		DBGC2_MD5A ( image, user_to_phys ( address, offset ),
			     user_to_virt ( address, offset ), initrd->len );
	}
	offset += initrd->len;

	/* Zero-pad to next INITRD_ALIGN boundary */
	pad_len = ( ( -offset ) & ( INITRD_ALIGN - 1 ) );
	if ( address )
		memset_user ( address, offset, 0, pad_len );

	return offset;
}

/**
 * Check that initrds can be loaded
 *
 * @v image		efistub image
 * @v leimg		efistub context
 * @ret rc		Return status code
 */
static int leimage_check_initrds ( struct image *image,
				   struct le_context *leimg ) {
	struct image *initrd;
	userptr_t bottom;
	size_t len = 0;
	int rc;

	/* Calculate total loaded length of initrds */
	for_each_image ( initrd ) {

		/* Skip kernel */
		if ( initrd == image )
			continue;

		/* Calculate length */
		len += leimage_load_initrd ( image, initrd, UNULL );
		len = leimage_align ( len );

		DBGC ( image, "efistub %p initrd %p from [%#08lx,%#08lx)%s%s\n",
		       image, initrd, user_to_phys ( initrd->data, 0 ),
		       user_to_phys ( initrd->data, initrd->len ),
		       ( initrd->cmdline ? " " : "" ),
		       ( initrd->cmdline ? initrd->cmdline : "" ) );
		DBGC2_MD5A ( image, user_to_phys ( initrd->data, 0 ),
			     user_to_virt ( initrd->data, 0 ), initrd->len );
	}

	/* Calculate lowest usable address */
	bottom = userptr_add ( leimg->kernel_addr, leimg->kernel_size );

	/* Check that total length fits within space available for
	 * reshuffling.  This is a conservative check, since CPIO
	 * headers are not present during reshuffling, but this
	 * doesn't hurt and keeps the code simple.
	 */
	if ( ( rc = initrd_reshuffle_check ( len, bottom ) ) != 0 ) {
		DBGC ( image, "efistub %p failed reshuffle check: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Check that total length fits within kernel's memory limit */
	if ( user_to_phys ( bottom, len ) > leimg->bzhdr->initrd_addr_max ) {
		DBGC ( image, "efistub %p not enough space for initrds\n",
		       image );
		return -ENOBUFS;
	}

	return 0;
}

/**
 * Load initrds, if any
 *
 * @v image		efistub image
 * @v leimg		efistub context
 */
static void leimage_load_initrds ( struct image *image,
				   struct le_context *leimg ) {
	struct image *initrd;
	struct image *highest = NULL;
	struct image *other;
	userptr_t top;
	userptr_t dest;
	size_t offset;
	size_t len;

	/* Reshuffle initrds into desired order */
	initrd_reshuffle ( userptr_add ( leimg->kernel_addr, leimg->kernel_size ) );

	/* Find highest initrd */
	for_each_image ( initrd ) {
		if ( ( highest == NULL ) ||
		     ( userptr_sub ( initrd->data, highest->data ) > 0 ) ) {
			highest = initrd;
		}
	}

	/* Do nothing if there are no initrds */
	if ( ! highest )
		return;

	/* Find highest usable address */
	top = userptr_add ( highest->data, leimage_align ( highest->len ) );
	if ( user_to_phys ( top, 0 ) > leimg->bzhdr->initrd_addr_max )
		top = phys_to_user ( leimg->bzhdr->initrd_addr_max );
	DBGC ( image, "efistub %p loading initrds from %#08lx downwards\n",
	       image, user_to_phys ( top, 0 ) );

	/* Load initrds in order */
	for_each_image ( initrd ) {

		/* Calculate cumulative length of following
		 * initrds (including padding).
		 */
		offset = 0;
		for_each_image ( other ) {
			if ( other == initrd )
				offset = 0;
			offset += leimage_load_initrd ( image, other, UNULL );
			offset = leimage_align ( offset );
		}

		/* Load initrd at this address */
		dest = userptr_add ( top, -offset );
		len = leimage_load_initrd ( image, initrd, dest );

		/* Record initrd location */
		if ( ! leimg->bzhdr->ramdisk_image )
			leimg->bzhdr->ramdisk_image = user_to_phys ( dest, 0 );
		leimg->bzhdr->ramdisk_size = ( user_to_phys ( dest, len ) -
					leimg->bzhdr->ramdisk_image );
	}
	DBGC ( image, "efistub %p initrds at [%#08x,%#08x)\n",
	       image, leimg->bzhdr->ramdisk_image,
	       ( leimg->bzhdr->ramdisk_image + leimg->bzhdr->ramdisk_size ) );
}

#if defined(__aarch64__)
static int set_up_boot ( struct le_context *ctx ) {
#error write me
	return 0;
}
#else
static int set_up_boot ( struct le_context *ctx ) {
	char *cmdline;
	int rc;

	cmdline = malloc (ctx->bzhdr->cmdline_size);
	if (!cmdline)
		return -ENOMEM;

	memcpy ( &ctx->params->linux_header, ctx->bzhdr, sizeof ( *ctx->bzhdr ) );

	cmdline[ctx->bzhdr->cmdline_size] = '\0';
	strncpy ( cmdline, ctx->image->cmdline, ctx->bzhdr->cmdline_size - 1 );

	memcpy ( &ctx->params->linux_header.setup_sects, ctx->bzhdr, 2 * 512 );

	ctx->params->linux_header.type_of_loader = BZI_LOADER_TYPE_IPXE;
	ctx->params->linux_header.cmd_line_ptr = (intptr_t)cmdline;

	ctx->params->linux_header.code32_start = (uint32_t)(intptr_t)ctx->kernel_addr;

	/* Check that initrds can be loaded */
	if ( ( rc = leimage_check_initrds ( ctx->image, ctx ) ) != 0 ) {
		free ( cmdline );
		return rc;
	}

	/* Load any initrds */
	leimage_load_initrds ( ctx->image, ctx );

	return 0;
}
#endif

/**
 * Execute Linux EFI Stub image
 *
 * @v image		Linux image w/ EFI stub
 * @ret rc		Return status code
 */
static int efistub_exec ( struct image *image ) {
	intptr_t kernel_addr = image->data;
	off_t handover_offset;
	off_t offset = 0;
#if defined(__aarch64__)
	struct linux_aarch64_kernel_header *bzhdr = (void *)kernel_addr;
	EFI_IMAGE_NT_HEADERS64 *pe = (void *)(kernel_addr + bzhdr->hdr_offset);
#else
	ssize_t start;
	struct bzimage_header *bzhdr = (void *)(kernel_addr + 0x1f1);
#endif
	struct le_context ctx;
	struct linux_kernel_params *params;
	void *kernel_mem;
	handover_func hf;
	int rc;

	params = malloc (16384);
	if (!params)
		return -ENOMEM;

	memset ( params , 0, sizeof ( *params ) );

#if defined(__aarch64__)
	handover_offset = pe->opt.entry_addr;
#else
	handover_offset = bzhdr->handover_offset;

	start = ( bzhdr->setup_sects + 1 ) * 512;
	kernel_mem = (void *)((intptr_t)image->data + start);
	ctx.kernel_size = image->len - start;
#endif

	ctx.image = image;
	ctx.bzhdr = bzhdr;
	ctx.params = params;
	ctx.kernel_addr = (userptr_t)kernel_mem;

	rc = set_up_boot ( &ctx );
	if (rc < 0) {
		free ( params );
		return rc;
	}

#ifdef __x86_64__
	offset = 0x200;
#endif

	hf = (handover_func)((intptr_t)kernel_mem + handover_offset + offset);

	/* Our image has no callback interface, so we need to shut
	 * down before invoking it.
	 */
	shutdown_boot();

	__asm__ __volatile__ ( "cli" );

	hf ( efi_image_handle, efi_systab, params );

	/* It isn't safe to continue after calling shutdown() */
	while ( 1 )
		;

	return -ECANCELED;  /* -EIMPOSSIBLE, anyone? */
}

#if !defined(__x86_64__) && !defined(__aarch64__)
static int pe32probe ( struct image *image , EFI_IMAGE_NT_HEADERS32 *pe ) {
	EFI_IMAGE_OPTIONAL_HEADER32 *opt = &pe->OptionalHeader;

	if ( opt->Magic != EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
		DBGC ( image, "Malformed PE Optional Header\n" );
		return -ENOEXEC;
	}

	if ( opt->Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ) {
		DBGC ( image, "Unsupported image type\n" );
		return -ENOEXEC;
	}

	return 0;
}
#endif

static int pe32plusprobe ( struct image *image , EFI_IMAGE_NT_HEADERS64 *pe ) {
	EFI_IMAGE_OPTIONAL_HEADER64 *opt = &pe->OptionalHeader;

	if ( opt->Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
		DBGC ( image, "Malformed PE Optional Header\n" );
		return -ENOEXEC;
	}

	if ( opt->Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ) {
		DBGC ( image, "Unsupported image type\n" );
		return -ENOEXEC;
	}

	return 0;
}
/**
 * Probe Linux EFI Stub image
 *
 * @v image		Linux EFI Stub file
 * @ret rc		Return status code
 */
static int efistub_probe ( struct image *image ) {
#if defined(__aarch64__)
	struct linux_aarch64_kernel_header bzhdr;
	EFI_IMAGE_NT_HEADERS64 pehdr;
#else
	EFI_IMAGE_DOS_HEADER mzhdr;
	EFI_IMAGE_OPTIONAL_HEADER_UNION pehdr;
	struct bzimage_header bzhdr;
#endif

	off_t pe_offset;
	int rc;

#if defined(__aarch64__)
	copy_from_user ( &bzhdr, image->data, 0, sizeof ( bzhdr ) );
	pe_offset = bzhdr.hdr_offset;
#else
	/* Read MZ header */
	copy_from_user ( &mzhdr, image->data, 0, sizeof ( mzhdr ) );
	if ( mzhdr.e_magic != EFI_IMAGE_DOS_SIGNATURE ) {
		DBGC ( image, "Invalid MZ identifier\n" );
		return -ENOEXEC;
	}
	pe_offset = mzhdr.e_lfanew;
#endif

	/* Read PE header */
	copy_from_user ( &pehdr, image->data, pe_offset, sizeof ( pehdr ) );
	if ( pehdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE ) {
		DBGC ( image, "Invalid PE identifier\n" );
		return -ENOEXEC;
	}

	switch ( pehdr.Pe32.FileHeader.Machine ) {
#if defined(__aarch64__)
	case IMAGE_FILE_MACHINE_ARM64:
		rc = pe32plusprobe ( image, &pehdr.Pe32Plus );
		break;
#else
#if !defined(__x86_64__)
	case IMAGE_FILE_MACHINE_I386:
		rc = pe32probe ( image, &pehdr.Pe32 );
		break;
#endif
	case IMAGE_FILE_MACHINE_X64:
		rc = pe32plusprobe ( image, &pehdr.Pe32Plus );
		break;
#endif
	default:
		DBGC ( image, "Unsupported machine type 0x%08x\n",
		       pehdr.Pe32.FileHeader.Machine );
		return -ENOEXEC;
	}

	if (rc < 0)
		return rc;

	/* Read our bzimage header */
	copy_from_user ( &bzhdr, image->data, 0x1f1, sizeof ( bzhdr ) );
	if ( memcmp ( &bzhdr.header, "HdrS", 4 ) ) {
		DBGC ( image, "Kernel is not supported\n" );
		return -ENOEXEC;
	}

	if ( bzhdr.boot_flag != 0xaa55 ) {
		DBGC ( image, "Invalid magic number\n" );
		return -ENOEXEC;
	}

	if ( bzhdr.kernel_version < 0x20c ) {
		DBGC ( image, "Kernel version %d.%d is too old\n",
		       bzhdr.kernel_version >> 8,
		       bzhdr.kernel_version & 0xff );
		return -ENOEXEC;
	}

#if defined(__x86_64__) || defined(__aarch64__)
	if ( ! ( bzhdr.xloadflags & LINUX_XLF_EFI_HANDOVER_64 ) ) {
		DBGC ( image, "Kernel does not have a 64-bit EFI entry point.\n" );
		return -ENOEXEC;
	}
#else
	if ( ! ( bzhdr.xloadflags & LINUX_XLF_EFI_HANDOVER_32 ) ) {
		DBGC ( image, "Kernel does not have a 32-bit EFI entry point.\n" );
		return -ENOEXEC;
	}
#endif

	if ( ! ( bzhdr.handover_offset ) ) {
		DBGC ( image, "Kernel does not have an EFI handover offset.\n");
		return -ENOEXEC;
	}

	return 0;
}

/** Linux EFI Stub image type */
struct image_type efistub_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "Linux EFI Stub",
	.probe = efistub_probe,
	.exec = efistub_exec,
};
