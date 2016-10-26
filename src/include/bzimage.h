#ifndef _BZIMAGE_H
#define _BZIMAGE_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#define LINUX_XLF_KERNEL_64                   (1<<0)
#define LINUX_XLF_CAN_BE_LOADED_ABOVE_4G      (1<<1)
#define LINUX_XLF_EFI_HANDOVER_32             (1<<2)
#define LINUX_XLF_EFI_HANDOVER_64             (1<<3)
#define LINUX_XLF_EFI_KEXEC                   (1<<4)

/**
 * A bzImage header
 *
 * As documented in Documentation/i386/boot.txt
 */
struct bzimage_header {
	/** The size of the setup in sectors
	 *
	 * If this field contains 0, assume it contains 4.
	 */
	uint8_t setup_sects;
	/** If set, the root is mounted readonly */
	uint16_t root_flags;
	/** DO NOT USE - for bootsect.S use only */
	uint16_t syssize;
	/** DO NOT USE - obsolete */
	uint16_t swap_dev;
	/** DO NOT USE - for bootsect.S use only */
	uint16_t ram_size;
	/** Video mode control */
	uint16_t vid_mode;
	/** Default root device number */
	uint16_t root_dev;
	/** 0xAA55 magic number */
	uint16_t boot_flag;
	/** Jump instruction */
	uint16_t jump;
	/** Magic signature "HdrS" */
	uint32_t header;
	/** Boot protocol version supported */
	uint16_t version;
	/** Boot loader hook (see below) */
	uint32_t realmode_swtch;
	/** The load-low segment (0x1000) (obsolete) */
	uint16_t start_sys;
	/** Pointer to kernel version string */
	uint16_t kernel_version;
	/** Boot loader identifier */
	uint8_t type_of_loader;
	/** Boot protocol option flags */
	uint8_t loadflags;
	/** Move to high memory size (used with hooks) */
	uint16_t setup_move_size;
	/** Boot loader hook (see below) */
	uint32_t code32_start;
	/** initrd load address (set by boot loader) */
	uint32_t ramdisk_image;
	/** initrd size (set by boot loader) */
	uint32_t ramdisk_size;
	/** DO NOT USE - for bootsect.S use only */
	uint32_t bootsect_kludge;
	/** Free memory after setup end */
	uint16_t heap_end_ptr;
	/** Unused */
	uint16_t pad1;
	/** 32-bit pointer to the kernel command line */
	uint32_t cmd_line_ptr;
	/** Highest legal initrd address */
	uint32_t initrd_addr_max;
	/** Physical addr alignment required for kernel	*/
	uint32_t kernel_alignment;
	/** Whether kernel is relocatable or not */
	uint8_t relocatable_kernel;
	/** Minimum alignment, as a power of two */
	uint8_t min_alignment;
	/** Boot protocol option flags */
	uint16_t xloadflags;
	/** Maximum size of the kernel command line */
	uint32_t cmdline_size;
	/** Hardware subarchitecture */
	uint32_t hardware_subarch;
	/** Subarchitecture-specific data */
	uint64_t hardware_subarch_data;
	/** Offset of kernel payload */
	uint32_t payload_offset;
	/** Length of kernel payload */
	uint32_t payload_length;
	/** 64-bit physical pointer to linked list of struct setup_data */
	uint64_t setup_data;
	/* Preferred loading address */
	uint64_t pref_address;
	/* Linear memory required during initialization */
	uint32_t init_size;
	/* Offset of handover entry point */
	uint32_t handover_offset;
} __attribute__ (( packed ));

struct linux_aarch64_kernel_header {
	uint32_t code0;
	uint32_t code1;
	uint64_t text_offset;
	uint64_t res0;
	uint64_t res1;
	uint64_t res2;
	uint64_t res3;
	uint64_t res4;
	uint32_t magic;
	uint32_t hdr_offset;
} __attribute__ (( packed ));

/** Offset of bzImage header within kernel image */
#define BZI_HDR_OFFSET 0x1f1

/** bzImage boot flag value */
#define BZI_BOOT_FLAG 0xaa55

/** bzImage magic signature value */
#define BZI_SIGNATURE 0x53726448

/** bzImage boot loader identifier for Etherboot */
#define BZI_LOADER_TYPE_ETHERBOOT 0x40

/** bzImage boot loader identifier for iPXE
 *
 * We advertise ourselves as Etherboot version 6.
 */
#define BZI_LOADER_TYPE_IPXE ( BZI_LOADER_TYPE_ETHERBOOT | 0x06 )

/** bzImage "load high" flag */
#define BZI_LOAD_HIGH 0x01

/** Load address for high-loaded kernels */
#define BZI_LOAD_HIGH_ADDR 0x100000

/** Load address for low-loaded kernels */
#define BZI_LOAD_LOW_ADDR 0x10000

/** bzImage "kernel can use heap" flag */
#define BZI_CAN_USE_HEAP 0x80

/** bzImage special video mode "normal" */
#define BZI_VID_MODE_NORMAL 0xffff

/** bzImage special video mode "ext" */
#define BZI_VID_MODE_EXT 0xfffe

/** bzImage special video mode "ask" */
#define BZI_VID_MODE_ASK 0xfffd

/** bzImage maximum initrd address for versions < 2.03 */
#define BZI_INITRD_MAX 0x37ffffff

/** bzImage command-line structure used by older kernels */
struct bzimage_cmdline {
	/** Magic signature */
	uint16_t magic;
	/** Offset to command line */
	uint16_t offset;
} __attribute__ (( packed ));

/** Offset of bzImage command-line structure within kernel image */
#define BZI_CMDLINE_OFFSET 0x20

/** bzImage command line present magic marker value */
#define BZI_CMDLINE_MAGIC 0xa33f

/** Assumed size of real-mode portion (including .bss) */
#define BZI_ASSUMED_RM_SIZE 0x8000

/** Amount of stack space to provide */
#define BZI_STACK_SIZE 0x1000

/** Maximum size of command line */
#define BZI_CMDLINE_SIZE 0x7ff


#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3
#define E820_NVS        4
#define E820_BADRAM     5

struct e820_mmap
{
  uint64_t addr;
  uint64_t size;
  uint32_t type;
} __attribute__ (( packed ));

enum
  {
    VIDEO_LINUX_TYPE_TEXT = 0x01,
    VIDEO_LINUX_TYPE_VESA = 0x23,    /* VESA VGA in graphic mode.  */
    VIDEO_LINUX_TYPE_EFIFB = 0x70,    /* EFI Framebuffer.  */
    VIDEO_LINUX_TYPE_SIMPLE = 0x70    /* Linear framebuffer without any additional functions.  */
  };

#define LINUX_LOADER_ID_LILO		0x0
#define LINUX_LOADER_ID_LOADLIN		0x1
#define LINUX_LOADER_ID_BOOTSECT	0x2
#define LINUX_LOADER_ID_SYSLINUX	0x3
#define LINUX_LOADER_ID_ETHERBOOT	0x4
#define LINUX_LOADER_ID_ELILO		0x5
#define LINUX_LOADER_ID_GRUB		0x7
#define LINUX_LOADER_ID_UBOOT		0x8
#define LINUX_LOADER_ID_XEN		0x9
#define LINUX_LOADER_ID_GUJIN		0xa
#define LINUX_LOADER_ID_QEMU		0xb

#define LINUX_XLF_KERNEL_64                   (1<<0)
#define LINUX_XLF_CAN_BE_LOADED_ABOVE_4G      (1<<1)
#define LINUX_XLF_EFI_HANDOVER_32             (1<<2)
#define LINUX_XLF_EFI_HANDOVER_64             (1<<3)
#define LINUX_XLF_EFI_KEXEC                   (1<<4)

/* Boot parameters for Linux based on 2.6.12. This is used by the setup
   sectors of Linux, and must be simulated by GRUB on EFI, because
   the setup sectors depend on BIOS.  */
struct linux_kernel_params
{
  uint8_t video_cursor_x;		/* 0 */
  uint8_t video_cursor_y;

  uint16_t ext_mem;		/* 2 */

  uint16_t video_page;		/* 4 */
  uint8_t video_mode;		/* 6 */
  uint8_t video_width;		/* 7 */

  uint8_t padding1[0xa - 0x8];

  uint16_t video_ega_bx;		/* a */

  uint8_t padding2[0xe - 0xc];

  uint8_t video_height;		/* e */
  uint8_t have_vga;		/* f */
  uint16_t font_size;		/* 10 */

  uint16_t lfb_width;		/* 12 */
  uint16_t lfb_height;		/* 14 */
  uint16_t lfb_depth;		/* 16 */
  uint32_t lfb_base;		/* 18 */
  uint32_t lfb_size;		/* 1c */

  uint16_t cl_magic;		/* 20 */
  uint16_t cl_offset;

  uint16_t lfb_line_len;		/* 24 */
  uint8_t red_mask_size;		/* 26 */
  uint8_t red_field_pos;
  uint8_t green_mask_size;
  uint8_t green_field_pos;
  uint8_t blue_mask_size;
  uint8_t blue_field_pos;
  uint8_t reserved_mask_size;
  uint8_t reserved_field_pos;
  uint16_t vesapm_segment;		/* 2e */
  uint16_t vesapm_offset;		/* 30 */
  uint16_t lfb_pages;		/* 32 */
  uint16_t vesa_attrib;		/* 34 */
  uint32_t capabilities;		/* 36 */

  uint8_t padding3[0x40 - 0x3a];

  uint16_t apm_version;		/* 40 */
  uint16_t apm_code_segment;	/* 42 */
  uint32_t apm_entry;		/* 44 */
  uint16_t apm_16bit_code_segment;	/* 48 */
  uint16_t apm_data_segment;	/* 4a */
  uint16_t apm_flags;		/* 4c */
  uint32_t apm_code_len;		/* 4e */
  uint16_t apm_data_len;		/* 52 */

  uint8_t padding4[0x60 - 0x54];

  uint32_t ist_signature;		/* 60 */
  uint32_t ist_command;		/* 64 */
  uint32_t ist_event;		/* 68 */
  uint32_t ist_perf_level;		/* 6c */

  uint8_t padding5[0x80 - 0x70];

  uint8_t hd0_drive_info[0x10];	/* 80 */
  uint8_t hd1_drive_info[0x10];	/* 90 */
  uint16_t rom_config_len;		/* a0 */

  uint8_t padding6[0xb0 - 0xa2];

  uint32_t ofw_signature;		/* b0 */
  uint32_t ofw_num_items;		/* b4 */
  uint32_t ofw_cif_handler;	/* b8 */
  uint32_t ofw_idt;		/* bc */

  uint8_t padding7[0x1b8 - 0xc0];

  union
    {
      struct
        {
          uint32_t efi_system_table;	/* 1b8 */
          uint32_t padding7_1;		/* 1bc */
          uint32_t efi_signature;		/* 1c0 */
          uint32_t efi_mem_desc_size;	/* 1c4 */
          uint32_t efi_mem_desc_version;	/* 1c8 */
          uint32_t efi_mmap_size;		/* 1cc */
          uint32_t efi_mmap;		/* 1d0 */
        } v0204;
      struct
        {
          uint32_t padding7_1;		/* 1b8 */
          uint32_t padding7_2;		/* 1bc */
          uint32_t efi_signature;		/* 1c0 */
          uint32_t efi_system_table;	/* 1c4 */
          uint32_t efi_mem_desc_size;	/* 1c8 */
          uint32_t efi_mem_desc_version;	/* 1cc */
          uint32_t efi_mmap;		/* 1d0 */
          uint32_t efi_mmap_size;		/* 1d4 */
	} v0206;
      struct
        {
          uint32_t padding7_1;		/* 1b8 */
          uint32_t padding7_2;		/* 1bc */
          uint32_t efi_signature;		/* 1c0 */
          uint32_t efi_system_table;	/* 1c4 */
          uint32_t efi_mem_desc_size;	/* 1c8 */
          uint32_t efi_mem_desc_version;	/* 1cc */
          uint32_t efi_mmap;		/* 1d0 */
          uint32_t efi_mmap_size;		/* 1d4 */
          uint32_t efi_system_table_hi;	/* 1d8 */
          uint32_t efi_mmap_hi;		/* 1dc */
        } v0208;
    };

  uint32_t alt_mem;		/* 1e0 */

  uint8_t padding8[0x1e8 - 0x1e4];

  uint8_t mmap_size;		/* 1e8 */

  uint8_t padding9[0x1f1 - 0x1e9];
  struct bzimage_header linux_header;
  uint8_t pad2[104];		/* 258 */
  struct e820_mmap e820_map[(0x400 - 0x2d0) / 20];	/* 2d0 */

} __attribute__ (( packed ));

#endif /* _BZIMAGE_H */
