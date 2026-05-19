"""
Function Pointer Resolver for Linux Kernel Drivers

Resolves indirect calls through kernel ops tables (file_operations, proto_ops,
net_device_ops, etc.) by:

1. Discovering ops struct definitions and their field signatures
2. Finding static initializer assignments: .read = my_read_handler
3. Finding dispatch call sites: file->f_op->read(...)
4. Connecting dispatch sites to all registered implementations

This is the critical missing piece for accurate call graph construction.
Without it, ~40-60% of security-relevant call edges are invisible.

The kernel uses a consistent pattern:
    // Registration (driver code)
    static const struct file_operations my_fops = {
        .owner = THIS_MODULE,
        .open = my_open,
        .read = my_read,
        .write = my_write,
        .unlocked_ioctl = my_ioctl,
        .release = my_release,
    };

    // Dispatch (VFS/core code)
    ret = filp->f_op->read(filp, buf, count, pos);

We parse both sides and connect them.

Usage:
    python -m extractors.fptr_resolver --kernel-path /path/to/linux --output data/fptr_edges.json

    # Or integrated into the pipeline:
    python -m extractors.fptr_resolver --kernel-path /path/to/linux \
        --graph data/callgraph.json --output data/callgraph_with_fptrs.json
"""

import argparse
import bisect
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "kernelsurgeon"))
from kernel_graph import KernelGraph, EdgeType


# ============================================================================
# KNOWN KERNEL OPS STRUCTS
#
# These are the major function pointer tables in the kernel. Each entry maps
# struct_name -> {field_name -> description}. We don't need the full type
# signature here because we resolve by (struct_type, field_name) pair.
#
# This covers ~90% of security-relevant indirect dispatch in the kernel.
# ============================================================================

KNOWN_OPS_STRUCTS = {
    # VFS / Filesystem
    "file_operations": {
        "owner": None,  # not a function pointer
        "llseek": "loff_t (*)(struct file *, loff_t, int)",
        "read": "ssize_t (*)(struct file *, char __user *, size_t, loff_t *)",
        "write": "ssize_t (*)(struct file *, const char __user *, size_t, loff_t *)",
        "read_iter": "ssize_t (*)(struct kiocb *, struct iov_iter *)",
        "write_iter": "ssize_t (*)(struct kiocb *, struct iov_iter *)",
        "unlocked_ioctl": "long (*)(struct file *, unsigned int, unsigned long)",
        "compat_ioctl": "long (*)(struct file *, unsigned int, unsigned long)",
        "mmap": "int (*)(struct file *, struct vm_area_struct *)",
        "open": "int (*)(struct inode *, struct file *)",
        "release": "int (*)(struct inode *, struct file *)",
        "flush": "int (*)(struct file *, fl_owner_t)",
        "fsync": "int (*)(struct file *, loff_t, loff_t, int)",
        "poll": "__poll_t (*)(struct file *, struct poll_table_struct *)",
        "splice_read": "ssize_t (*)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int)",
        "splice_write": "ssize_t (*)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int)",
        "sendpage": "ssize_t (*)(struct file *, struct page *, int, size_t, loff_t *, int)",
        "fallocate": "long (*)(struct file *, int, loff_t, loff_t)",
    },
    "inode_operations": {
        "lookup": "struct dentry *(*)(struct inode *, struct dentry *, unsigned int)",
        "create": "int (*)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool)",
        "link": "int (*)(struct dentry *, struct inode *, struct dentry *)",
        "unlink": "int (*)(struct inode *, struct dentry *)",
        "symlink": "int (*)(struct mnt_idmap *, struct inode *, struct dentry *, const char *)",
        "mkdir": "int (*)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t)",
        "rmdir": "int (*)(struct inode *, struct dentry *)",
        "rename": "int (*)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int)",
        "permission": "int (*)(struct mnt_idmap *, struct inode *, int)",
        "getattr": "int (*)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int)",
        "setattr": "int (*)(struct mnt_idmap *, struct dentry *, struct iattr *)",
        "listxattr": "ssize_t (*)(struct dentry *, char *, size_t)",
        "fiemap": "int (*)(struct inode *, struct fiemap_extent_info *, u64, u64)",
    },
    "super_operations": {
        "alloc_inode": "struct inode *(*)(struct super_block *)",
        "destroy_inode": "void (*)(struct inode *)",
        "free_inode": "void (*)(struct inode *)",
        "dirty_inode": "void (*)(struct inode *, int)",
        "write_inode": "int (*)(struct inode *, struct writeback_control *)",
        "drop_inode": "int (*)(struct inode *)",
        "evict_inode": "void (*)(struct inode *)",
        "put_super": "void (*)(struct super_block *)",
        "sync_fs": "int (*)(struct super_block *, int)",
        "statfs": "int (*)(struct dentry *, struct kstatfs *)",
        "remount_fs": "int (*)(struct super_block *, int *, char *)",
        "show_options": "int (*)(struct seq_file *, struct dentry *)",
    },
    "address_space_operations": {
        "writepage": "int (*)(struct page *, struct writeback_control *)",
        "read_folio": "int (*)(struct file *, struct folio *)",
        "writepages": "int (*)(struct address_space *, struct writeback_control *)",
        "dirty_folio": "bool (*)(struct address_space *, struct folio *)",
        "readahead": "void (*)(struct readahead_control *)",
        "write_begin": "int (*)(struct file *, struct address_space *, loff_t, unsigned, struct page **, void **)",
        "write_end": "int (*)(struct file *, struct address_space *, loff_t, unsigned, unsigned, struct page *, void *)",
        "direct_IO": "ssize_t (*)(struct kiocb *, struct iov_iter *)",
    },
    "vm_operations_struct": {
        "open": "void (*)(struct vm_area_struct *)",
        "close": "void (*)(struct vm_area_struct *)",
        "fault": "vm_fault_t (*)(struct vm_fault *)",
        "huge_fault": "vm_fault_t (*)(struct vm_fault *, unsigned int)",
        "map_pages": "vm_fault_t (*)(struct vm_fault *, pgoff_t, pgoff_t)",
        "page_mkwrite": "vm_fault_t (*)(struct vm_fault *)",
        "pfn_mkwrite": "vm_fault_t (*)(struct vm_fault *)",
        "access": "int (*)(struct vm_area_struct *, unsigned long, void *, int, int)",
    },

    # Networking
    "proto_ops": {
        "family": None,
        "owner": None,
        "release": "int (*)(struct socket *)",
        "bind": "int (*)(struct socket *, struct sockaddr *, int)",
        "connect": "int (*)(struct socket *, struct sockaddr *, int, int)",
        "accept": "int (*)(struct socket *, struct socket *, int, bool)",
        "getname": "int (*)(struct socket *, struct sockaddr *, int)",
        "poll": "__poll_t (*)(struct file *, struct socket *, struct poll_table_struct *)",
        "ioctl": "int (*)(struct socket *, unsigned int, unsigned long)",
        "listen": "int (*)(struct socket *, int)",
        "shutdown": "int (*)(struct socket *, int)",
        "setsockopt": "int (*)(struct socket *, int, int, sockptr_t, unsigned int)",
        "getsockopt": "int (*)(struct socket *, int, int, char __user *, int __user *)",
        "sendmsg": "int (*)(struct socket *, struct msghdr *, size_t)",
        "recvmsg": "int (*)(struct socket *, struct msghdr *, size_t, int)",
        "mmap": "int (*)(struct file *, struct socket *, struct vm_area_struct *)",
    },
    "net_device_ops": {
        "ndo_open": "int (*)(struct net_device *)",
        "ndo_stop": "int (*)(struct net_device *)",
        "ndo_start_xmit": "netdev_tx_t (*)(struct sk_buff *, struct net_device *)",
        "ndo_set_mac_address": "int (*)(struct net_device *, void *)",
        "ndo_do_ioctl": "int (*)(struct net_device *, struct ifreq *, int)",
        "ndo_eth_ioctl": "int (*)(struct net_device *, struct ifreq *, int)",
        "ndo_siocdevprivate": "int (*)(struct net_device *, struct ifreq *, void __user *, int)",
        "ndo_set_rx_mode": "void (*)(struct net_device *)",
        "ndo_get_stats64": "void (*)(struct net_device *, struct rtnl_link_stats64 *)",
        "ndo_change_mtu": "int (*)(struct net_device *, int)",
        "ndo_tx_timeout": "void (*)(struct net_device *, unsigned int)",
        "ndo_bpf": "int (*)(struct net_device *, struct netdev_bpf *)",
        "ndo_xdp_xmit": "int (*)(struct net_device *, int, struct xdp_frame **, u32)",
    },
    "ethtool_ops": {
        "get_drvinfo": "void (*)(struct net_device *, struct ethtool_drvinfo *)",
        "get_link": "u32 (*)(struct net_device *)",
        "get_strings": "void (*)(struct net_device *, u32, u8 *)",
        "get_ethtool_stats": "void (*)(struct net_device *, struct ethtool_stats *, u64 *)",
        "get_ringparam": "void (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)",
        "set_ringparam": "int (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)",
    },
    "nf_hook_ops": {
        "hook": "unsigned int (*)(void *, struct sk_buff *, const struct nf_hook_state *)",
    },

    # Block / IO
    "block_device_operations": {
        "open": "int (*)(struct gendisk *, blk_mode_t)",
        "release": "void (*)(struct gendisk *)",
        "ioctl": "int (*)(struct block_device *, blk_mode_t, unsigned, unsigned long)",
        "compat_ioctl": "int (*)(struct block_device *, blk_mode_t, unsigned, unsigned long)",
        "submit_bio": "void (*)(struct bio *)",
        "getgeo": "int (*)(struct block_device *, struct hd_geometry *)",
        "owner": None,
    },

    # Device driver model
    "platform_driver": {
        "probe": "int (*)(struct platform_device *)",
        "remove": "void (*)(struct platform_device *)",
        "shutdown": "void (*)(struct platform_device *)",
        "suspend": "int (*)(struct platform_device *, pm_message_t)",
        "resume": "int (*)(struct platform_device *)",
        "driver": None,  # nested struct, not fptr
    },
    "pci_driver": {
        "probe": "int (*)(struct pci_dev *, const struct pci_device_id *)",
        "remove": "void (*)(struct pci_dev *)",
        "shutdown": "void (*)(struct pci_dev *)",
        "suspend": "int (*)(struct pci_dev *, pm_message_t)",
        "resume": "int (*)(struct pci_dev *)",
        "err_handler": None,
        "driver": None,
    },
    "usb_driver": {
        "probe": "int (*)(struct usb_interface *, const struct usb_device_id *)",
        "disconnect": "void (*)(struct usb_interface *)",
        "suspend": "int (*)(struct usb_interface *, pm_message_t)",
        "resume": "int (*)(struct usb_interface *)",
        "reset_resume": "int (*)(struct usb_interface *)",
        "pre_reset": "int (*)(struct usb_interface *)",
        "post_reset": "int (*)(struct usb_interface *)",
    },

    # Security
    "security_hook_list": {
        "hook": None,  # complex, handled separately
    },

    # Char device
    "tty_operations": {
        "open": "int (*)(struct tty_struct *, struct file *)",
        "close": "void (*)(struct tty_struct *, struct file *)",
        "write": "ssize_t (*)(struct tty_struct *, const u8 *, size_t)",
        "write_room": "unsigned int (*)(struct tty_struct *)",
        "ioctl": "int (*)(struct tty_struct *, unsigned int, unsigned long)",
        "set_termios": "void (*)(struct tty_struct *, const struct ktermios *)",
        "throttle": "void (*)(struct tty_struct *)",
        "unthrottle": "void (*)(struct tty_struct *)",
        "hangup": "void (*)(struct tty_struct *)",
    },

    # IIO (Industrial I/O - common in embedded/sensor drivers)
    "iio_info": {
        "read_raw": "int (*)(struct iio_dev *, struct iio_chan_spec const *, int *, int *, long)",
        "write_raw": "int (*)(struct iio_dev *, struct iio_chan_spec const *, int, int, long)",
        "read_event_config": "int (*)(struct iio_dev *, const struct iio_chan_spec *, enum iio_event_type, enum iio_event_direction)",
        "write_event_config": "int (*)(struct iio_dev *, const struct iio_chan_spec *, enum iio_event_type, enum iio_event_direction, int)",
    },

    # Sequential / proc filesystem
    "seq_operations": {
        "start": "void *(*)(struct seq_file *, loff_t *)",
        "stop": "void (*)(struct seq_file *, void *)",
        "next": "void *(*)(struct seq_file *, void *, loff_t *)",
        "show": "int (*)(struct seq_file *, void *)",
    },
    "proc_ops": {
        "proc_open": "int (*)(struct inode *, struct file *)",
        "proc_read": "ssize_t (*)(struct file *, char __user *, size_t, loff_t *)",
        "proc_read_iter": "ssize_t (*)(struct kiocb *, struct iov_iter *)",
        "proc_write": "ssize_t (*)(struct file *, const char __user *, size_t, loff_t *)",
        "proc_lseek": "loff_t (*)(struct file *, loff_t, int)",
        "proc_release": "int (*)(struct inode *, struct file *)",
        "proc_poll": "__poll_t (*)(struct file *, struct poll_table_struct *)",
        "proc_ioctl": "long (*)(struct file *, unsigned int, unsigned long)",
        "proc_compat_ioctl": "long (*)(struct file *, unsigned int, unsigned long)",
        "proc_mmap": "int (*)(struct file *, struct vm_area_struct *)",
        "proc_get_unmapped_area": "unsigned long (*)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long)",
    },

    # Kobject / sysfs
    "kobj_type": {
        "release": "void (*)(struct kobject *)",
        "show": "ssize_t (*)(struct kobject *, struct attribute *, char *)",
        "store": "ssize_t (*)(struct kobject *, struct attribute *, const char *, size_t)",
    },
    "sysfs_ops": {
        "show": "ssize_t (*)(struct kobject *, struct attribute *, char *)",
        "store": "ssize_t (*)(struct kobject *, struct attribute *, const char *, size_t)",
    },

    # Device model
    "bus_type": {
        "match": "int (*)(struct device *, struct device_driver *)",
        "uevent": "int (*)(const struct device *, struct kobj_uevent_env *)",
        "probe": "int (*)(struct device *)",
        "sync_state": "void (*)(struct device *)",
        "remove": "void (*)(struct device *)",
        "shutdown": "void (*)(struct device *)",
        "online": "int (*)(struct device *)",
        "offline": "int (*)(struct device *)",
        "suspend": "int (*)(struct device *, pm_message_t)",
        "resume": "int (*)(struct device *)",
        "num_vf": "int (*)(struct device *)",
        "dma_configure": "int (*)(struct device *)",
        "dma_cleanup": "void (*)(struct device *)",
    },
    "device_driver": {
        "probe": "int (*)(struct device *)",
        "sync_state": "void (*)(struct device *)",
        "remove": "void (*)(struct device *)",
        "shutdown": "void (*)(struct device *)",
        "suspend": "int (*)(struct device *, pm_message_t)",
        "resume": "int (*)(struct device *)",
        "coredump": "void (*)(struct device *)",
    },

    # UART / TTY line discipline
    "uart_ops": {
        "tx_empty": "unsigned int (*)(struct uart_port *)",
        "set_mctrl": "void (*)(struct uart_port *, unsigned int)",
        "get_mctrl": "unsigned int (*)(struct uart_port *)",
        "stop_tx": "void (*)(struct uart_port *)",
        "start_tx": "void (*)(struct uart_port *)",
        "throttle": "void (*)(struct uart_port *)",
        "unthrottle": "void (*)(struct uart_port *)",
        "send_xchar": "void (*)(struct uart_port *, char)",
        "stop_rx": "void (*)(struct uart_port *)",
        "enable_ms": "void (*)(struct uart_port *)",
        "break_ctl": "void (*)(struct uart_port *, int)",
        "startup": "int (*)(struct uart_port *)",
        "shutdown": "void (*)(struct uart_port *)",
        "flush_buffer": "void (*)(struct uart_port *)",
        "set_termios": "void (*)(struct uart_port *, struct ktermios *, const struct ktermios *)",
        "set_ldisc": "void (*)(struct uart_port *, struct ktermios *)",
        "pm": "void (*)(struct uart_port *, unsigned int, unsigned int)",
        "type": "const char *(*)(struct uart_port *)",
        "release_port": "void (*)(struct uart_port *)",
        "request_port": "int (*)(struct uart_port *)",
        "config_port": "void (*)(struct uart_port *, int)",
        "verify_port": "int (*)(struct uart_port *, struct serial_struct *)",
        "ioctl": "int (*)(struct uart_port *, unsigned int, unsigned long)",
    },
    "tty_ldisc_ops": {
        "open": "int (*)(struct tty_struct *)",
        "close": "void (*)(struct tty_struct *)",
        "flush_buffer": "void (*)(struct tty_struct *)",
        "read": "ssize_t (*)(struct tty_struct *, struct file *, u8 __user *, size_t, void **, unsigned long)",
        "write": "ssize_t (*)(struct tty_struct *, struct file *, const u8 *, size_t)",
        "ioctl": "int (*)(struct tty_struct *, unsigned int, unsigned long)",
        "compat_ioctl": "long (*)(struct tty_struct *, unsigned int, unsigned long)",
        "set_termios": "void (*)(struct tty_struct *, const struct ktermios *)",
        "poll": "__poll_t (*)(struct tty_struct *, struct file *, struct poll_table_struct *)",
        "hangup": "void (*)(struct tty_struct *)",
        "receive_buf": "void (*)(struct tty_struct *, const u8 *, const u8 *, size_t)",
        "write_wakeup": "void (*)(struct tty_struct *)",
        "dcd_change": "void (*)(struct tty_struct *, bool)",
        "receive_buf2": "size_t (*)(struct tty_struct *, const u8 *, const u8 *, size_t)",
        "lookahead_buf": "void (*)(struct tty_struct *, const u8 *, const u8 *, size_t)",
    },

    # Framebuffer
    "fb_ops": {
        "fb_open": "int (*)(struct fb_info *, int)",
        "fb_release": "int (*)(struct fb_info *, int)",
        "fb_read": "ssize_t (*)(struct fb_info *, char __user *, size_t, loff_t *)",
        "fb_write": "ssize_t (*)(struct fb_info *, const char __user *, size_t, loff_t *)",
        "fb_check_var": "int (*)(struct fb_var_screeninfo *, struct fb_info *)",
        "fb_set_par": "int (*)(struct fb_info *)",
        "fb_setcolreg": "int (*)(unsigned, unsigned, unsigned, unsigned, unsigned, struct fb_info *)",
        "fb_setcmap": "int (*)(struct fb_cmap *, struct fb_info *)",
        "fb_blank": "int (*)(int, struct fb_info *)",
        "fb_pan_display": "int (*)(struct fb_var_screeninfo *, struct fb_info *)",
        "fb_fillrect": "void (*)(struct fb_info *, const struct fb_fillrect *)",
        "fb_copyarea": "void (*)(struct fb_info *, const struct fb_copyarea *)",
        "fb_imageblit": "void (*)(struct fb_info *, const struct fb_image *)",
        "fb_cursor": "int (*)(struct fb_info *, struct fb_cursor *)",
        "fb_sync": "int (*)(struct fb_info *)",
        "fb_ioctl": "int (*)(struct fb_info *, unsigned int, unsigned long)",
        "fb_compat_ioctl": "int (*)(struct fb_info *, unsigned int, unsigned long)",
        "fb_mmap": "int (*)(struct fb_info *, struct vm_area_struct *)",
        "fb_get_caps": "void (*)(struct fb_info *, struct fb_blit_caps *, struct fb_var_screeninfo *)",
        "fb_destroy": "void (*)(struct fb_info *)",
    },

    # DRM / GPU
    "drm_driver": {
        "open": "int (*)(struct drm_device *, struct drm_file *)",
        "postclose": "void (*)(struct drm_device *, struct drm_file *)",
        "lastclose": "void (*)(struct drm_device *)",
        "unload": "void (*)(struct drm_device *)",
        "release": "void (*)(struct drm_device *)",
        "get_vblank_counter": "u32 (*)(struct drm_device *, unsigned int)",
        "enable_vblank": "int (*)(struct drm_device *, unsigned int)",
        "disable_vblank": "void (*)(struct drm_device *, unsigned int)",
        "get_vblank_timestamp": "bool (*)(struct drm_device *, unsigned int, int *, ktime_t *, bool)",
        "gem_open_object": "int (*)(struct drm_gem_object *, struct drm_file *)",
        "gem_close_object": "void (*)(struct drm_gem_object *, struct drm_file *)",
        "gem_print_info": "void (*)(struct drm_printer *, unsigned int, const struct drm_gem_object *)",
        "gem_create_object": "struct drm_gem_object *(*)(struct drm_device *, size_t)",
        "prime_handle_to_fd": "int (*)(struct drm_device *, struct drm_file *, uint32_t, uint32_t, int *)",
        "prime_fd_to_handle": "int (*)(struct drm_device *, struct drm_file *, int, uint32_t *)",
        "gem_prime_import": "struct drm_gem_object *(*)(struct drm_device *, struct dma_buf *)",
        "gem_prime_export": "struct dma_buf *(*)(struct drm_gem_object *, int)",
        "dumb_create": "int (*)(struct drm_file *, struct drm_device *, struct drm_mode_create_dumb *)",
        "dumb_map_offset": "int (*)(struct drm_file *, struct drm_device *, uint32_t, uint64_t *)",
        "show_fdinfo": "void (*)(struct drm_printer *, struct drm_file *)",
    },

    # V4L2 (Video for Linux)
    "v4l2_subdev_ops": {
        "registered": "int (*)(struct v4l2_subdev *)",
        "unregistered": "void (*)(struct v4l2_subdev *)",
        "open": "int (*)(struct v4l2_subdev *, struct v4l2_subdev_fh *)",
        "close": "int (*)(struct v4l2_subdev *, struct v4l2_subdev_fh *)",
        "s_clock_freq": "int (*)(struct v4l2_subdev *, u32)",
        "g_std": "int (*)(struct v4l2_subdev *, v4l2_std_id *)",
        "s_std": "int (*)(struct v4l2_subdev *, v4l2_std_id)",
        "s_stream": "int (*)(struct v4l2_subdev *, int)",
        "g_frame_interval": "int (*)(struct v4l2_subdev *, struct v4l2_subdev_frame_interval *)",
        "s_frame_interval": "int (*)(struct v4l2_subdev *, struct v4l2_subdev_frame_interval *)",
        "g_mbus_config": "int (*)(struct v4l2_subdev *, unsigned int, struct v4l2_mbus_config *)",
    },
    "media_entity_operations": {
        "get_fwnode_pad": "int (*)(struct media_entity *, struct fwnode_endpoint *)",
        "link_setup": "int (*)(struct media_entity *, const struct media_pad *, const struct media_pad *, u32)",
        "link_validate": "int (*)(struct media_link *)",
        "has_pad_interdep": "bool (*)(struct media_entity *, unsigned int, unsigned int)",
    },

    # ALSA Sound
    "snd_pcm_ops": {
        "open": "int (*)(struct snd_pcm_substream *)",
        "close": "int (*)(struct snd_pcm_substream *)",
        "hw_params": "int (*)(struct snd_pcm_substream *, struct snd_pcm_hw_params *)",
        "hw_free": "int (*)(struct snd_pcm_substream *)",
        "prepare": "int (*)(struct snd_pcm_substream *)",
        "trigger": "int (*)(struct snd_pcm_substream *, int)",
        "sync_stop": "int (*)(struct snd_pcm_substream *)",
        "pointer": "snd_pcm_uframes_t (*)(struct snd_pcm_substream *)",
        "get_time_info": "int (*)(struct snd_pcm_substream *, struct timespec64 *, struct timespec64 *, struct snd_pcm_audio_tstamp_config *, struct snd_pcm_audio_tstamp_report *)",
        "fill_silence": "int (*)(struct snd_pcm_substream *, int, unsigned long, unsigned long)",
        "copy": "int (*)(struct snd_pcm_substream *, int, unsigned long, struct iov_iter *, unsigned long)",
        "ack": "int (*)(struct snd_pcm_substream *)",
    },
    "snd_soc_dai_ops": {
        "set_sysclk": "int (*)(struct snd_soc_dai *, int, unsigned int, int)",
        "set_pll": "int (*)(struct snd_soc_dai *, int, int, unsigned int, unsigned int)",
        "set_clkdiv": "int (*)(struct snd_soc_dai *, int, int)",
        "set_bclk_ratio": "int (*)(struct snd_soc_dai *, unsigned int)",
        "set_fmt": "int (*)(struct snd_soc_dai *, unsigned int)",
        "xlate_tdm_slot_mask": "int (*)(unsigned int, unsigned int *, unsigned int *)",
        "set_tdm_slot": "int (*)(struct snd_soc_dai *, unsigned int, unsigned int, int, int)",
        "set_channel_map": "int (*)(struct snd_soc_dai *, unsigned int, unsigned int *, unsigned int, unsigned int *)",
        "set_tristate": "int (*)(struct snd_soc_dai *, int)",
        "digital_mute": "int (*)(struct snd_soc_dai *, int, int)",
        "mute_stream": "int (*)(struct snd_soc_dai *, int, int)",
        "startup": "int (*)(struct snd_pcm_substream *, struct snd_soc_dai *)",
        "shutdown": "void (*)(struct snd_pcm_substream *, struct snd_soc_dai *)",
        "hw_params": "int (*)(struct snd_pcm_substream *, struct snd_pcm_hw_params *, struct snd_soc_dai *)",
        "hw_free": "int (*)(struct snd_pcm_substream *, struct snd_soc_dai *)",
        "prepare": "int (*)(struct snd_pcm_substream *, struct snd_soc_dai *)",
        "trigger": "int (*)(struct snd_pcm_substream *, int, struct snd_soc_dai *)",
        "bespoke_trigger": "int (*)(struct snd_pcm_substream *, int, struct snd_soc_dai *)",
        "compress_new": "int (*)(struct snd_soc_pcm_runtime *, int)",
    },

    # Crypto
    "crypto_alg": {
        "cra_init": "int (*)(struct crypto_tfm *)",
        "cra_exit": "void (*)(struct crypto_tfm *)",
        "cra_destroy": "void (*)(struct crypto_alg *)",
    },
    "shash_alg": {
        "init": "int (*)(struct shash_desc *)",
        "update": "int (*)(struct shash_desc *, const u8 *, unsigned int)",
        "final": "int (*)(struct shash_desc *, u8 *)",
        "finup": "int (*)(struct shash_desc *, const u8 *, unsigned int, u8 *)",
        "digest": "int (*)(struct shash_desc *, const u8 *, unsigned int, u8 *)",
        "export": "int (*)(struct shash_desc *, void *)",
        "import": "int (*)(struct shash_desc *, const void *)",
        "setkey": "int (*)(struct crypto_shash *, const u8 *, unsigned int)",
        "init_tfm": "int (*)(struct crypto_shash *)",
        "exit_tfm": "void (*)(struct crypto_shash *)",
    },
    "skcipher_alg": {
        "setkey": "int (*)(struct crypto_skcipher *, const u8 *, unsigned int)",
        "encrypt": "int (*)(struct skcipher_request *)",
        "decrypt": "int (*)(struct skcipher_request *)",
        "init": "int (*)(struct crypto_skcipher *)",
        "exit": "void (*)(struct crypto_skcipher *)",
    },

    # Networking — transport / socket layer
    "proto": {
        "close": "void (*)(struct sock *, long)",
        "pre_connect": "int (*)(struct sock *, struct sockaddr *, int)",
        "connect": "int (*)(struct sock *, struct sockaddr *, int)",
        "disconnect": "int (*)(struct sock *, int)",
        "accept": "struct sock *(*)(struct sock *, struct proto_accept_arg *)",
        "ioctl": "int (*)(struct sock *, int, int *)",
        "init": "int (*)(struct sock *, int, gfp_t)",
        "destroy": "void (*)(struct sock *)",
        "shutdown": "void (*)(struct sock *, int)",
        "setsockopt": "int (*)(struct sock *, int, int, sockptr_t, unsigned int)",
        "getsockopt": "int (*)(struct sock *, int, int, char __user *, int __user *)",
        "sendmsg": "int (*)(struct sock *, struct msghdr *, size_t)",
        "recvmsg": "int (*)(struct sock *, struct msghdr *, size_t, int, int *)",
        "sendpage": "int (*)(struct sock *, struct page *, int, size_t, int)",
        "bind": "int (*)(struct sock *, struct sockaddr *, int)",
        "bind_add": "int (*)(struct sock *, struct sockaddr *, int)",
        "backlog_rcv": "int (*)(struct sock *, struct sk_buff *)",
        "release_cb": "void (*)(struct sock *)",
        "hash": "int (*)(struct sock *)",
        "unhash": "void (*)(struct sock *)",
        "get_port": "int (*)(struct sock *, unsigned short)",
        "put_port": "void (*)(struct sock *)",
        "diag_destroy": "int (*)(struct sock *, int)",
        "keepalive": "void (*)(struct sock *, int)",
        "compat_ioctl": "int (*)(struct sock *, unsigned int, unsigned long)",
    },
    "net_proto_family": {
        "create": "int (*)(struct net *, struct socket *, int, int)",
    },
    "neigh_ops": {
        "output": "int (*)(struct neighbour *, struct sk_buff *)",
        "connected_output": "int (*)(struct neighbour *, struct sk_buff *)",
        "error_output": "int (*)(struct neighbour *, struct sk_buff *)",
        "hh_output": "int (*)(const struct hh_cache *, struct sk_buff *)",
        "queue_xmit": "int (*)(struct sk_buff *)",
        "error_report": "void (*)(struct neighbour *)",
        "solicit": "void (*)(struct neighbour *, struct sk_buff *)",
        "confirm": "void (*)(struct neighbour *)",
    },
    "dst_ops": {
        "family": None,
        "gc": "int (*)(struct dst_ops *)",
        "gc_thresh": None,
        "check": "struct dst_entry *(*)(struct dst_entry *, __u32)",
        "default_advmss": "unsigned int (*)(const struct dst_entry *)",
        "mtu": "unsigned int (*)(const struct dst_entry *)",
        "cow_metrics": "struct mutex *(*)(struct dst_entry *, unsigned long)",
        "destroy": "void (*)(struct dst_entry *)",
        "ifdown": "void (*)(struct dst_entry *, bool)",
        "negative_advice": "void (*)(struct sock *, struct dst_entry *)",
        "link_failure": "void (*)(struct sk_buff *)",
        "update_pmtu": "void (*)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool)",
        "redirect": "void (*)(struct dst_entry *, struct sock *, struct sk_buff *)",
        "local_out": "int (*)(struct net *, struct sock *, struct sk_buff *)",
        "neigh_lookup": "struct neighbour *(*)(const struct dst_entry *, struct sk_buff *, const void *)",
    },
    "packet_type": {
        "func": "int (*)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *)",
        "id_match": "bool (*)(struct packet_type *, struct sock *)",
    },

    # SCSI / ATA storage
    "scsi_host_template": {
        "queuecommand": "int (*)(struct Scsi_Host *, struct scsi_cmnd *)",
        "eh_timed_out": "scsi_timeout_action (*)(struct scsi_cmnd *)",
        "eh_abort_handler": "int (*)(struct scsi_cmnd *)",
        "eh_device_reset_handler": "int (*)(struct scsi_cmnd *)",
        "eh_target_reset_handler": "int (*)(struct scsi_cmnd *)",
        "eh_bus_reset_handler": "int (*)(struct scsi_cmnd *)",
        "eh_host_reset_handler": "int (*)(struct scsi_cmnd *)",
        "slave_alloc": "int (*)(struct scsi_device *)",
        "slave_configure": "int (*)(struct scsi_device *)",
        "slave_destroy": "void (*)(struct scsi_device *)",
        "target_alloc": "int (*)(struct scsi_target *)",
        "target_destroy": "void (*)(struct scsi_target *)",
        "scan_finished": "int (*)(struct Scsi_Host *, unsigned long)",
        "scan_start": "void (*)(struct Scsi_Host *)",
        "change_queue_depth": "int (*)(struct scsi_device *, int)",
        "map_queues": "int (*)(struct Scsi_Host *)",
        "mq_poll": "int (*)(struct blk_mq_hw_ctx *, const struct io_comp_batch *, unsigned int)",
        "commit_rqs": "void (*)(struct Scsi_Host *, u16)",
        "proc_info": "int (*)(struct Scsi_Host *, char *, char **, off_t, int, int)",
        "show_info": "int (*)(struct seq_file *, struct Scsi_Host *)",
        "write_info": "ssize_t (*)(struct Scsi_Host *, const char *, size_t)",
        "host_reset": "int (*)(struct Scsi_Host *, int)",
        "bios_param": "int (*)(struct scsi_device *, struct block_device *, sector_t, int [])",
        "init_cmd_priv": "int (*)(struct Scsi_Host *, struct scsi_cmnd *)",
        "exit_cmd_priv": "void (*)(struct Scsi_Host *, struct scsi_cmnd *)",
    },
    "ata_port_operations": {
        "qc_defer": "int (*)(struct ata_queued_cmd *)",
        "qc_prep": "enum ata_completion_errors (*)(struct ata_queued_cmd *)",
        "qc_issue": "unsigned int (*)(struct ata_queued_cmd *)",
        "qc_fill_rtf": "void (*)(struct ata_queued_cmd *)",
        "qc_ncq_fill_rtf": "void (*)(struct ata_port *, u64)",
        "cable_detect": "int (*)(struct ata_port *)",
        "mode_filter": "unsigned long (*)(struct ata_device *, unsigned long)",
        "set_piomode": "void (*)(struct ata_port *, struct ata_device *)",
        "set_dmamode": "void (*)(struct ata_port *, struct ata_device *)",
        "set_mode": "int (*)(struct ata_link *, struct ata_device **)",
        "dev_config": "unsigned int (*)(struct ata_device *)",
        "freeze": "void (*)(struct ata_port *)",
        "thaw": "void (*)(struct ata_port *)",
        "error_handler": "void (*)(struct ata_port *)",
        "lost_interrupt": "void (*)(struct ata_port *)",
        "post_internal_cmd": "void (*)(struct ata_queued_cmd *)",
        "sched_eh": "void (*)(struct ata_port *)",
        "end_eh": "void (*)(struct ata_port *)",
        "scr_read": "int (*)(struct ata_link *, unsigned int, u32 *)",
        "scr_write": "int (*)(struct ata_link *, unsigned int, u32)",
        "pmp_attach": "int (*)(struct ata_port *)",
        "pmp_detach": "void (*)(struct ata_port *)",
        "port_start": "int (*)(struct ata_port *)",
        "port_stop": "void (*)(struct ata_port *)",
        "host_stop": "void (*)(struct ata_host *)",
        "sff_dev_select": "void (*)(struct ata_port *, unsigned int)",
        "sff_set_devctl": "void (*)(struct ata_port *, u8)",
        "sff_check_status": "u8 (*)(struct ata_port *)",
        "sff_check_altstatus": "u8 (*)(struct ata_port *)",
        "sff_tf_load": "void (*)(struct ata_port *, const struct ata_taskfile *)",
        "sff_tf_read": "void (*)(struct ata_port *, struct ata_taskfile *)",
        "sff_exec_command": "void (*)(struct ata_port *, const struct ata_taskfile *)",
        "sff_data_xfer": "unsigned int (*)(struct ata_queued_cmd *, unsigned char *, unsigned int, int)",
        "sff_irq_on": "u8 (*)(struct ata_port *)",
        "sff_irq_check": "bool (*)(struct ata_port *)",
        "sff_drain_fifo": "void (*)(struct ata_queued_cmd *)",
    },

    # IRQ / DMA
    "irq_chip": {
        "irq_startup": "unsigned int (*)(struct irq_data *)",
        "irq_shutdown": "void (*)(struct irq_data *)",
        "irq_enable": "void (*)(struct irq_data *)",
        "irq_disable": "void (*)(struct irq_data *)",
        "irq_ack": "void (*)(struct irq_data *)",
        "irq_mask": "void (*)(struct irq_data *)",
        "irq_mask_ack": "void (*)(struct irq_data *)",
        "irq_unmask": "void (*)(struct irq_data *)",
        "irq_eoi": "void (*)(struct irq_data *)",
        "irq_set_affinity": "int (*)(struct irq_data *, const struct cpumask *, bool)",
        "irq_retrigger": "int (*)(struct irq_data *)",
        "irq_set_type": "int (*)(struct irq_data *, unsigned int)",
        "irq_set_wake": "int (*)(struct irq_data *, unsigned int)",
        "irq_bus_lock": "void (*)(struct irq_data *)",
        "irq_bus_sync_unlock": "void (*)(struct irq_data *)",
        "irq_suspend": "void (*)(struct irq_data *)",
        "irq_resume": "void (*)(struct irq_data *)",
        "irq_pm_shutdown": "void (*)(struct irq_data *)",
        "irq_calc_mask": "void (*)(struct irq_data *)",
        "irq_print_chip": "void (*)(struct irq_data *, struct seq_file *)",
        "irq_request_resources": "int (*)(struct irq_data *)",
        "irq_release_resources": "void (*)(struct irq_data *)",
        "irq_compose_msi_msg": "void (*)(struct irq_data *, struct msi_msg *)",
        "irq_write_msi_msg": "void (*)(struct irq_data *, struct msi_msg *)",
        "irq_get_irqchip_state": "int (*)(struct irq_data *, enum irqchip_irq_state, bool *)",
        "irq_set_irqchip_state": "int (*)(struct irq_data *, enum irqchip_irq_state, bool)",
        "irq_set_vcpu_affinity": "int (*)(struct irq_data *, void *)",
        "ipi_send_single": "void (*)(struct irq_data *, unsigned int)",
        "ipi_send_mask": "void (*)(struct irq_data *, const struct cpumask *)",
        "irq_nmi_setup": "int (*)(struct irq_data *)",
        "irq_nmi_teardown": "void (*)(struct irq_data *)",
    },
    "dma_map_ops": {
        "alloc": "void *(*)(struct device *, size_t, dma_addr_t *, gfp_t, unsigned long)",
        "free": "void (*)(struct device *, size_t, void *, dma_addr_t, unsigned long)",
        "alloc_pages": "struct page *(*)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t)",
        "free_pages": "void (*)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction)",
        "alloc_noncoherent": "void *(*)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t)",
        "free_noncoherent": "void (*)(struct device *, size_t, void *, dma_addr_t, enum dma_data_direction)",
        "mmap": "int (*)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, unsigned long)",
        "get_sgtable": "int (*)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, unsigned long)",
        "map_page": "dma_addr_t (*)(struct device *, struct page *, unsigned long, size_t, enum dma_data_direction, unsigned long)",
        "unmap_page": "void (*)(struct device *, dma_addr_t, size_t, enum dma_data_direction, unsigned long)",
        "map_sg": "int (*)(struct device *, struct scatterlist *, int, enum dma_data_direction, unsigned long)",
        "unmap_sg": "void (*)(struct device *, struct scatterlist *, int, enum dma_data_direction, unsigned long)",
        "map_resource": "dma_addr_t (*)(struct device *, phys_addr_t, size_t, enum dma_data_direction, unsigned long)",
        "unmap_resource": "void (*)(struct device *, dma_addr_t, size_t, enum dma_data_direction, unsigned long)",
        "sync_single_for_cpu": "void (*)(struct device *, dma_addr_t, size_t, enum dma_data_direction)",
        "sync_single_for_device": "void (*)(struct device *, dma_addr_t, size_t, enum dma_data_direction)",
        "sync_sg_for_cpu": "void (*)(struct device *, struct scatterlist *, int, enum dma_data_direction)",
        "sync_sg_for_device": "void (*)(struct device *, struct scatterlist *, int, enum dma_data_direction)",
        "cache_sync": "void (*)(struct device *, void *, size_t, enum dma_data_direction)",
        "dma_supported": "int (*)(struct device *, u64)",
        "get_required_mask": "u64 (*)(struct device *)",
        "max_mapping_size": "size_t (*)(struct device *)",
        "opt_mapping_size": "size_t (*)(void)",
        "get_merge_boundary": "unsigned long (*)(struct device *)",
    },

    # I2C / SPI buses
    "i2c_driver": {
        "probe": "int (*)(struct i2c_client *)",
        "remove": "void (*)(struct i2c_client *)",
        "shutdown": "void (*)(struct i2c_client *)",
        "alert": "void (*)(struct i2c_client *, enum i2c_alert_protocol, unsigned int)",
        "command": "int (*)(struct i2c_client *, unsigned int, void *)",
        "detect": "int (*)(struct i2c_client *, struct i2c_board_info *)",
    },
    "spi_driver": {
        "probe": "int (*)(struct spi_device *)",
        "remove": "void (*)(struct spi_device *)",
        "shutdown": "void (*)(struct spi_device *)",
        "optimize_message": "int (*)(struct spi_message *)",
    },

    # RTC / Watchdog
    "rtc_class_ops": {
        "ioctl": "int (*)(struct device *, unsigned int, unsigned long)",
        "read_time": "int (*)(struct device *, struct rtc_time *)",
        "set_time": "int (*)(struct device *, struct rtc_time *)",
        "read_alarm": "int (*)(struct device *, struct rtc_wkalrm *)",
        "set_alarm": "int (*)(struct device *, struct rtc_wkalrm *)",
        "proc": "int (*)(struct device *, struct seq_file *)",
        "set_mmss64": "int (*)(struct device *, time64_t)",
        "read_callback": "int (*)(struct device *, int)",
        "alarm_irq_enable": "int (*)(struct device *, unsigned int)",
        "read_offset": "int (*)(struct device *, long *)",
        "set_offset": "int (*)(struct device *, long)",
    },
    "watchdog_ops": {
        "start": "int (*)(struct watchdog_device *)",
        "stop": "int (*)(struct watchdog_device *)",
        "ping": "int (*)(struct watchdog_device *)",
        "status": "unsigned int (*)(struct watchdog_device *)",
        "set_timeout": "int (*)(struct watchdog_device *, unsigned int)",
        "set_pretimeout": "int (*)(struct watchdog_device *, unsigned int)",
        "get_timeleft": "unsigned int (*)(struct watchdog_device *)",
        "restart": "int (*)(struct watchdog_device *, unsigned long, void *)",
        "ioctl": "long (*)(struct watchdog_device *, unsigned int, unsigned long)",
    },

    # Filesystem extras
    "xattr_handler": {
        "list": "bool (*)(struct dentry *)",
        "get": "int (*)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t)",
        "set": "int (*)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int)",
    },
    "export_operations": {
        "encode_fh": "int (*)(struct inode *, __u32 *, int *, struct inode *)",
        "fh_to_dentry": "struct dentry *(*)(struct super_block *, struct fid *, int, int)",
        "fh_to_parent": "struct dentry *(*)(struct super_block *, struct fid *, int, int)",
        "get_name": "int (*)(struct dentry *, char *, struct dentry *)",
        "get_parent": "struct dentry *(*)(struct dentry *)",
        "commit_metadata": "int (*)(struct inode *)",
        "get_uuid": "int (*)(struct super_block *, u8 *, u32 *, u64 *)",
        "map_blocks": "int (*)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *)",
        "commit_blocks": "int (*)(struct inode *, struct iomap *, int, struct iattr *)",
    },
    "file_lock_operations": {
        "fl_copy_lock": "void (*)(struct file_lock *, struct file_lock *)",
        "fl_release_private": "void (*)(struct file_lock *)",
    },
    "quota_format_ops": {
        "check_quota_file": "int (*)(struct super_block *, int)",
        "read_file_info": "int (*)(struct super_block *, int)",
        "write_file_info": "int (*)(struct super_block *, int)",
        "free_file_info": "void (*)(struct super_block *, int)",
        "read_dqblk": "int (*)(struct dquot *)",
        "commit_dqblk": "int (*)(struct dquot *)",
        "release_dqblk": "int (*)(struct dquot *)",
        "get_next_id": "int (*)(struct super_block *, struct kqid *)",
    },

    # Memory management
    "mmu_notifier_ops": {
        "release": "void (*)(struct mmu_notifier *, struct mm_struct *)",
        "clear_flush_young": "int (*)(struct mmu_notifier *, struct mm_struct *, unsigned long, unsigned long)",
        "clear_young": "int (*)(struct mmu_notifier *, struct mm_struct *, unsigned long, unsigned long)",
        "test_young": "int (*)(struct mmu_notifier *, struct mm_struct *, unsigned long)",
        "change_pte": "void (*)(struct mmu_notifier *, struct mm_struct *, unsigned long, pte_t)",
        "invalidate_range_start": "int (*)(struct mmu_notifier *, const struct mmu_notifier_range *)",
        "invalidate_range_end": "void (*)(struct mmu_notifier *, const struct mmu_notifier_range *)",
        "invalidate_range": "void (*)(struct mmu_notifier *, struct mm_struct *, unsigned long, unsigned long)",
        "alloc_notifier": "struct mmu_notifier *(*)(struct mm_struct *)",
        "free_notifier": "void (*)(struct mmu_notifier *)",
    },
}


@dataclass
class OpsRegistration:
    """A concrete function pointer assignment found in source code."""
    struct_type: str          # e.g. "file_operations"
    field_name: str           # e.g. "read"
    target_function: str      # e.g. "my_read"
    source_file: str
    line_number: int
    instance_name: str = ""   # e.g. "my_fops"
    is_static_init: bool = True


@dataclass
class OpsDispatch:
    """An indirect call site dispatching through an ops table."""
    struct_type: str          # e.g. "file_operations"
    field_name: str           # e.g. "read"
    caller_function: str      # function containing the dispatch
    source_file: str
    line_number: int
    dispatch_expression: str  # e.g. "filp->f_op->read"


@dataclass
class FptrEdge:
    """A resolved function pointer edge."""
    dispatch_file: str
    dispatch_function: str
    dispatch_line: int
    target_function: str
    target_file: str
    struct_type: str
    field_name: str
    confidence: str           # "high" (static init), "medium" (runtime assign), "low" (type match)


class FunctionPointerResolver:
    """
    Resolves kernel function pointer dispatch tables.
    
    Phase 1: Scan source for ops struct static initializers
    Phase 2: Scan source for dispatch call sites
    Phase 3: Connect dispatches to implementations
    Phase 4: Optionally discover new ops structs from source
    """

    # ====================================================================
    # REGEX PATTERNS
    # ====================================================================

    # Static initializer block:
    # static const struct file_operations my_fops = {
    #     .read = my_read,
    #     .write = my_write,
    # };
    STRUCT_INIT_START = re.compile(
        r'(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+(\w+)\s*=\s*\{',
    )

    # Field assignment within initializer: .field_name = function_name
    FIELD_ASSIGN = re.compile(
        r'\.(\w+)\s*=\s*(\w+)\s*[,}]',
    )

    # Runtime field assignment: ptr->field = function_name or struct.field = function_name
    RUNTIME_ASSIGN = re.compile(
        r'(?:(\w+)(?:->|\.))?(\w+)\s*=\s*(\w+)\s*;',
    )

    # Dispatch call patterns:
    # ptr->ops->method(args)
    # ptr->f_op->read(args)
    # sb->s_op->alloc_inode(args)
    DISPATCH_PATTERN = re.compile(
        r'(\w+)->(\w+)->(\w+)\s*\(',
    )

    # Alternative dispatch: ops.method(args) or ops->method(args)
    DISPATCH_DIRECT = re.compile(
        r'(\w+)(?:->|\.)(\w+)\s*\(',
    )

    # Known pointer-to-ops field mappings in kernel structs
    # e.g., struct file has f_op pointing to file_operations
    OPS_FIELD_MAP = {
        # VFS / filesystem
        "f_op": "file_operations",
        "i_op": "inode_operations",
        "s_op": "super_operations",
        "a_ops": "address_space_operations",
        "vm_ops": "vm_operations_struct",
        "fops": "file_operations",
        "proc_fops": "file_operations",
        "file_operations": "file_operations",

        # Networking
        "ops": None,            # ambiguous, resolved by context
        "netdev_ops": "net_device_ops",
        "ethtool_ops": "ethtool_ops",
        "ndo_ops": "net_device_ops",
        "sk_prot": "proto",
        "prot": "proto",
        "family": "net_proto_family",
        "nops": "neigh_ops",
        "dst_ops": "dst_ops",

        # Block / TTY
        "driver": None,         # could be many types
        "blk_fops": "block_device_operations",
        "fops_": "block_device_operations",
        "tty_ops": "tty_operations",
        "ldisc": "tty_ldisc_ops",
        "l_ops": "tty_ldisc_ops",
        "uart_ops": "uart_ops",

        # proc / seq
        "seq_ops": "seq_operations",
        "proc_ops": "proc_ops",

        # Kobject / sysfs
        "ktype": "kobj_type",
        "sysfs_ops": "sysfs_ops",

        # Device model
        "bus_type": "bus_type",
        "drv": "device_driver",

        # Framebuffer / DRM
        "fb_ops": "fb_ops",
        "fbops": "fb_ops",
        "drm_driver": "drm_driver",

        # V4L2
        "subdev_ops": "v4l2_subdev_ops",
        "entity_ops": "media_entity_operations",

        # Sound
        "pcm_ops": "snd_pcm_ops",
        "dai_ops": "snd_soc_dai_ops",

        # Crypto
        "cra_u": None,          # union, too ambiguous
        "alg": "crypto_alg",

        # IRQ / DMA
        "irq_chip": "irq_chip",
        "chip": "irq_chip",
        "dma_ops": "dma_map_ops",
        "dev_ops": "dma_map_ops",

        # I2C / SPI / RTC / Watchdog
        "rtc_ops": "rtc_class_ops",
        "wdt_ops": "watchdog_ops",
        "watchdog_ops": "watchdog_ops",

        # Platform / PCI / USB
        "platform_driver": "platform_driver",
        "pci_driver": "pci_driver",
        "usb_driver": "usb_driver",

        # IIO
        "info": "iio_info",
    }

    def __init__(self, kernel_path: str, subsystems: list[str] | None = None):
        self.kernel_path = Path(kernel_path).resolve()
        self.subsystems = subsystems

        self.registrations: list[OpsRegistration] = []
        self.dispatches: list[OpsDispatch] = []
        self.resolved_edges: list[FptrEdge] = []

        # Index: (struct_type, field_name) -> [target_functions]
        self._reg_index: dict[tuple[str, str], list[OpsRegistration]] = defaultdict(list)

        # Index: struct_type -> set of known field names
        self._known_fields: dict[str, set[str]] = {}
        for struct_type, fields in KNOWN_OPS_STRUCTS.items():
            self._known_fields[struct_type] = {
                f for f, sig in fields.items() if sig is not None
            }

        # Stats
        self._files_scanned = 0
        self._structs_discovered = 0

    def _iter_source_files(self) -> list[Path]:
        """Get all C source files to scan."""
        patterns = self.subsystems or [
            "kernel/", "mm/", "fs/", "net/", "drivers/", "security/",
            "ipc/", "block/", "crypto/", "lib/", "sound/",
        ]
        files = []
        for pattern in patterns:
            search_dir = self.kernel_path / pattern
            if not search_dir.exists():
                continue
            for cfile in search_dir.rglob("*.c"):
                files.append(cfile)
        return files

    def _get_relative_path(self, path: Path) -> str:
        """Get path relative to kernel root."""
        try:
            return str(path.relative_to(self.kernel_path))
        except ValueError:
            return str(path)

    def _build_func_line_index(self, ctags_path: Path | None = None) -> None:
        """
        Build a file→[(line, func_name)] index from the ctags tags file.

        This replaces the O(200)-per-dispatch backward line-walking with
        an O(log N) bisect lookup.  If the tags file doesn't exist, falls
        back to a regex-based index built during the file scan.
        """
        self._func_line_index: dict[str, list[tuple[int, str]]] = defaultdict(list)

        if ctags_path is None:
            ctags_path = self.kernel_path / "tags"

        if ctags_path.exists():
            with open(ctags_path, errors="ignore") as fh:
                for line in fh:
                    if line.startswith("!"):
                        continue
                    parts = line.split("\t")
                    if len(parts) < 3:
                        continue
                    name = parts[0]
                    filepath = parts[1]
                    try:
                        rel_path = str(Path(filepath).relative_to(self.kernel_path))
                    except ValueError:
                        rel_path = filepath
                    # Extract line number
                    line_num = 0
                    for part in parts[2:]:
                        part = part.strip()
                        if part.isdigit():
                            line_num = int(part)
                            break
                        m = re.search(r'line:(\d+)', part)
                        if m:
                            line_num = int(m.group(1))
                            break
                    if line_num:
                        self._func_line_index[rel_path].append((line_num, name))

            # Sort each file's entries by line number for bisect
            for entries in self._func_line_index.values():
                entries.sort()

    def _identify_enclosing_function_fast(self, file_path: str, target_line: int) -> str:
        """
        O(log N) enclosing function lookup via bisect on the ctags index.
        Falls back to ``<unknown>`` if the index has no data for this file.
        """
        entries = self._func_line_index.get(file_path, [])
        if not entries:
            return "<unknown>"
        # Find the rightmost entry with line <= target_line
        idx = bisect.bisect_right(entries, (target_line + 1,)) - 1
        if idx >= 0:
            return entries[idx][1]
        return "<unknown>"

    def _identify_enclosing_function(self, lines: list[str], target_line: int) -> str:
        """
        Regex fallback: walk backwards to find the function definition.
        Only used when ctags index is unavailable for this file.
        """
        func_def_pattern = re.compile(
            r'^(?:static\s+)?(?:inline\s+)?(?:__always_inline\s+)?'
            r'(?:(?:void|int|long|unsigned|ssize_t|bool|__poll_t|vm_fault_t|'
            r'netdev_tx_t|loff_t|struct\s+\w+\s*\*?)\s+)'
            r'(\w+)\s*\('
        )

        for i in range(target_line - 1, max(0, target_line - 200), -1):
            if i >= len(lines):
                continue
            match = func_def_pattern.match(lines[i])
            if match:
                return match.group(1)

        return "<unknown>"

    # ====================================================================
    # PHASE 1: Find ops struct registrations (static initializers)
    # ====================================================================

    def scan_registrations(self) -> None:
        """Scan all source files for ops struct static initializer blocks."""
        print("[*] Phase 1: Scanning for ops struct registrations...")
        files = self._iter_source_files()

        for source_file in files:
            try:
                content = source_file.read_text(errors="ignore")
            except Exception:
                continue

            self._files_scanned += 1
            rel_path = self._get_relative_path(source_file)
            lines = content.split("\n")

            self._scan_static_initializers(lines, rel_path)
            self._scan_runtime_assignments(lines, rel_path)

        print(f"    Scanned {self._files_scanned} files")
        print(f"    Found {len(self.registrations)} function pointer registrations")

        # Build index
        for reg in self.registrations:
            key = (reg.struct_type, reg.field_name)
            self._reg_index[key].append(reg)

        # Report top struct types
        type_counts = defaultdict(int)
        for reg in self.registrations:
            type_counts[reg.struct_type] += 1
        top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:10]
        for stype, count in top_types:
            print(f"      {stype}: {count} registrations")

    def _scan_static_initializers(self, lines: list[str], file_path: str) -> None:
        """Parse static struct initializers like: struct file_operations fops = { .read = handler, }"""
        in_init = False
        current_struct = ""
        current_instance = ""
        brace_depth = 0

        for line_num, line in enumerate(lines):
            stripped = line.strip()

            if not in_init:
                # Look for struct initializer start
                match = self.STRUCT_INIT_START.search(stripped)
                if match:
                    struct_type = match.group(1)
                    instance_name = match.group(2)

                    # Only process known ops structs
                    if struct_type in KNOWN_OPS_STRUCTS:
                        in_init = True
                        current_struct = struct_type
                        current_instance = instance_name
                        brace_depth = stripped.count("{") - stripped.count("}")
                        self._structs_discovered += 1

                        # Check for field assignments on the same line
                        for field_match in self.FIELD_ASSIGN.finditer(stripped):
                            self._record_field_assignment(
                                struct_type, field_match.group(1),
                                field_match.group(2), file_path,
                                line_num, instance_name,
                            )
            else:
                # Inside an initializer block
                brace_depth += stripped.count("{") - stripped.count("}")

                # Look for field assignments
                for field_match in self.FIELD_ASSIGN.finditer(stripped):
                    self._record_field_assignment(
                        current_struct, field_match.group(1),
                        field_match.group(2), file_path,
                        line_num, current_instance,
                    )

                # Check if initializer block ended
                if brace_depth <= 0 or "};" in stripped:
                    in_init = False
                    current_struct = ""

    def _scan_runtime_assignments(self, lines: list[str], file_path: str) -> None:
        """
        Scan for runtime function pointer assignments like:
            dev->netdev_ops = &my_netdev_ops;
            sk->sk_prot->sendmsg = my_sendmsg;
        """
        for line_num, line in enumerate(lines):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            match = self.RUNTIME_ASSIGN.search(stripped)
            if not match:
                continue

            prefix = match.group(1) or ""
            field = match.group(2)
            target = match.group(3)

            # Check if the field name matches a known ops field
            struct_type = self.OPS_FIELD_MAP.get(field)
            if struct_type and target.startswith("&"):
                # This assigns an entire ops struct, not individual fields
                # e.g., dev->netdev_ops = &my_ops;
                continue

            # Check if field is a known function pointer field in any ops struct
            for stype, fields in KNOWN_OPS_STRUCTS.items():
                if field in fields and fields[field] is not None:
                    # Verify target looks like a function name
                    if re.match(r'^[a-zA-Z_]\w*$', target) and \
                       target not in ("NULL", "true", "false", "0", "1", "THIS_MODULE"):
                        self.registrations.append(OpsRegistration(
                            struct_type=stype,
                            field_name=field,
                            target_function=target,
                            source_file=file_path,
                            line_number=line_num,
                            instance_name=prefix,
                            is_static_init=False,
                        ))
                    break

    def _record_field_assignment(
        self, struct_type: str, field_name: str, target: str,
        file_path: str, line_num: int, instance_name: str,
    ) -> None:
        """Record a single .field = target assignment if valid."""
        known_fields = self._known_fields.get(struct_type, set())

        # Only record if it's a known function pointer field
        if field_name not in known_fields:
            return

        # Filter out non-function targets
        if target in ("NULL", "0", "THIS_MODULE", "true", "false"):
            return
        if not re.match(r'^[a-zA-Z_]\w*$', target):
            return

        self.registrations.append(OpsRegistration(
            struct_type=struct_type,
            field_name=field_name,
            target_function=target,
            source_file=file_path,
            line_number=line_num,
            instance_name=instance_name,
            is_static_init=True,
        ))

    # ====================================================================
    # PHASE 2: Find dispatch call sites
    # ====================================================================

    def _scan_dispatch_lines(
        self,
        lines: list[str],
        rel_path: str,
    ) -> list[OpsDispatch]:
        """
        Scan lines for dispatch call sites.  Returns a list of OpsDispatch
        (thread-safe: no mutation of self).
        """
        dispatches: list[OpsDispatch] = []
        has_fast_index = bool(self._func_line_index.get(rel_path))

        for line_num, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for match in self.DISPATCH_PATTERN.finditer(stripped):
                obj_name = match.group(1)
                ops_field = match.group(2)
                method = match.group(3)

                struct_type = self.OPS_FIELD_MAP.get(ops_field)
                if struct_type is None:
                    struct_type = self._infer_struct_type(ops_field, method)

                if struct_type and method in self._known_fields.get(struct_type, set()):
                    if has_fast_index:
                        caller = self._identify_enclosing_function_fast(rel_path, line_num)
                    else:
                        caller = self._identify_enclosing_function(lines, line_num)
                    dispatches.append(OpsDispatch(
                        struct_type=struct_type,
                        field_name=method,
                        caller_function=caller,
                        source_file=rel_path,
                        line_number=line_num,
                        dispatch_expression=f"{obj_name}->{ops_field}->{method}",
                    ))

        return dispatches

    def scan_dispatches(self) -> None:
        """Scan for indirect call dispatch sites through ops tables."""
        print("[*] Phase 2: Scanning for dispatch call sites...")
        files = self._iter_source_files()

        for source_file in files:
            try:
                content = source_file.read_text(errors="ignore")
            except Exception:
                continue

            rel_path = self._get_relative_path(source_file)
            lines = content.split("\n")
            self.dispatches.extend(self._scan_dispatch_lines(lines, rel_path))

        print(f"    Found {len(self.dispatches)} dispatch call sites")

        type_counts = defaultdict(int)
        for d in self.dispatches:
            type_counts[d.struct_type] += 1
        for stype, count in sorted(type_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"      {stype}: {count} dispatch sites")

    def _infer_struct_type(self, ops_field: str, method: str) -> Optional[str]:
        """Try to infer the ops struct type from field and method names."""
        # Check if method exists in any known struct
        candidates = []
        for stype, fields in KNOWN_OPS_STRUCTS.items():
            if method in fields and fields[method] is not None:
                candidates.append(stype)

        if len(candidates) == 1:
            return candidates[0]

        # Ambiguous — use naming heuristics
        if "f_op" in ops_field or "fops" in ops_field:
            return "file_operations"
        if "i_op" in ops_field:
            return "inode_operations"
        if "s_op" in ops_field:
            return "super_operations"
        if "netdev" in ops_field:
            return "net_device_ops"

        return None

    # ====================================================================
    # PHASE 3: Resolve — connect dispatches to implementations
    # ====================================================================

    def resolve(self) -> list[FptrEdge]:
        """Connect dispatch call sites to registered implementations."""
        print("[*] Phase 3: Resolving function pointer targets...")
        self.resolved_edges = []

        resolved_count = 0
        unresolved_count = 0

        for dispatch in self.dispatches:
            key = (dispatch.struct_type, dispatch.field_name)
            targets = self._reg_index.get(key, [])

            if not targets:
                unresolved_count += 1
                continue

            for target in targets:
                edge = FptrEdge(
                    dispatch_file=dispatch.source_file,
                    dispatch_function=dispatch.caller_function,
                    dispatch_line=dispatch.line_number,
                    target_function=target.target_function,
                    target_file=target.source_file,
                    struct_type=dispatch.struct_type,
                    field_name=dispatch.field_name,
                    confidence="high" if target.is_static_init else "medium",
                )
                self.resolved_edges.append(edge)
                resolved_count += 1

        print(f"    Resolved {resolved_count} function pointer edges")
        print(f"    Unresolved dispatch sites: {unresolved_count}")

        # Unique target functions reached
        unique_targets = set(e.target_function for e in self.resolved_edges)
        unique_dispatchers = set(e.dispatch_function for e in self.resolved_edges)
        print(f"    Unique target functions: {len(unique_targets)}")
        print(f"    Unique dispatch functions: {len(unique_dispatchers)}")

        return self.resolved_edges

    # ====================================================================
    # PHASE 4: Discover new ops structs from source (optional)
    # ====================================================================

    def discover_ops_structs(self) -> dict[str, list[str]]:
        """
        Scan kernel headers for struct definitions containing function pointers.
        Discovers ops structs not in the hardcoded list.
        """
        print("[*] Phase 4: Discovering additional ops structs...")
        discovered = {}

        include_dirs = [
            self.kernel_path / "include" / "linux",
            self.kernel_path / "include" / "net",
            self.kernel_path / "include" / "uapi",
        ]

        fptr_field_pattern = re.compile(
            r'^\s+\w[\w\s\*]+\(\*(\w+)\)\s*\(',
        )

        struct_start = re.compile(r'^struct\s+(\w+)\s*\{')

        for include_dir in include_dirs:
            if not include_dir.exists():
                continue

            for hfile in include_dir.rglob("*.h"):
                try:
                    lines = hfile.read_text(errors="ignore").split("\n")
                except Exception:
                    continue

                current_struct = None
                fptr_fields = []
                brace_depth = 0

                for line in lines:
                    if current_struct is None:
                        match = struct_start.match(line)
                        if match:
                            name = match.group(1)
                            # Heuristic: ops structs usually have "ops" or "operations" in name
                            if ("ops" in name.lower() or "operations" in name.lower()
                                    or name.endswith("_driver")):
                                current_struct = name
                                fptr_fields = []
                                brace_depth = line.count("{") - line.count("}")
                    else:
                        brace_depth += line.count("{") - line.count("}")

                        fptr_match = fptr_field_pattern.match(line)
                        if fptr_match:
                            fptr_fields.append(fptr_match.group(1))

                        if brace_depth <= 0:
                            if (fptr_fields and current_struct not in KNOWN_OPS_STRUCTS):
                                discovered[current_struct] = fptr_fields
                            current_struct = None

        print(f"    Discovered {len(discovered)} additional ops structs")
        for name, fields in list(discovered.items())[:10]:
            print(f"      {name}: {len(fields)} function pointer fields")

        return discovered

    # ====================================================================
    # INTEGRATION: Add resolved edges to KernelGraph
    # ====================================================================

    def integrate_into_graph(self, graph: KernelGraph) -> int:
        """
        Add resolved function pointer edges to an existing KernelGraph.
        Returns number of edges added.
        """
        print("[*] Integrating function pointer edges into call graph...")
        added = 0
        skipped_no_node = 0

        for edge in self.resolved_edges:
            # Find dispatch function node
            dispatch_ids = graph.lookup_function(edge.dispatch_function)
            if not dispatch_ids:
                # Try to add it
                if edge.dispatch_file and edge.dispatch_file != "<unknown>":
                    dispatch_id = graph.add_function(
                        name=edge.dispatch_function,
                        file_path=edge.dispatch_file,
                        line_start=edge.dispatch_line,
                    )
                    dispatch_ids = [dispatch_id]
                else:
                    skipped_no_node += 1
                    continue

            # Find target function node
            target_ids = graph.lookup_function(edge.target_function)
            if not target_ids:
                target_id = graph.add_function(
                    name=edge.target_function,
                    file_path=edge.target_file,
                )
                target_ids = [target_id]

            # Add edges
            for did in dispatch_ids:
                for tid in target_ids:
                    graph.add_call_edge(
                        did, tid,
                        edge_type=EdgeType.INDIRECT_CALL,
                        call_site_line=edge.dispatch_line,
                    )
                    added += 1

        print(f"    Added {added} function pointer edges")
        print(f"    Skipped (no dispatch node): {skipped_no_node}")

        return added

    # ====================================================================
    # FULL PIPELINE
    # ====================================================================

    # ====================================================================
    # COMBINED SINGLE-PASS SCAN (parallel I/O)
    # ====================================================================

    def _scan_all(self) -> None:
        """
        Single-pass scan: find registrations AND dispatches in one file read.

        Uses ThreadPoolExecutor for I/O parallelism — Python releases the
        GIL during ``read_text()`` so threads genuinely overlap disk I/O.
        """
        print("[*] Scanning for registrations and dispatches (single-pass, parallel I/O)...")
        files = self._iter_source_files()

        def _process_file(source_file: Path):
            """Thread worker: scan one file for both registrations and dispatches."""
            try:
                content = source_file.read_text(errors="ignore")
            except Exception:
                return [], []

            rel_path = self._get_relative_path(source_file)
            lines = content.split("\n")

            # --- Registrations ---
            local_regs: list[OpsRegistration] = []

            # Static initializers
            in_init = False
            current_struct = ""
            current_instance = ""
            brace_depth = 0

            for line_num, line in enumerate(lines):
                stripped = line.strip()
                if not in_init:
                    match = self.STRUCT_INIT_START.search(stripped)
                    if match:
                        struct_type = match.group(1)
                        instance_name = match.group(2)
                        if struct_type in KNOWN_OPS_STRUCTS:
                            in_init = True
                            current_struct = struct_type
                            current_instance = instance_name
                            brace_depth = stripped.count("{") - stripped.count("}")
                            for fm in self.FIELD_ASSIGN.finditer(stripped):
                                reg = self._make_registration(
                                    current_struct, fm.group(1), fm.group(2),
                                    rel_path, line_num, instance_name, True,
                                )
                                if reg:
                                    local_regs.append(reg)
                else:
                    brace_depth += stripped.count("{") - stripped.count("}")
                    for fm in self.FIELD_ASSIGN.finditer(stripped):
                        reg = self._make_registration(
                            current_struct, fm.group(1), fm.group(2),
                            rel_path, line_num, current_instance, True,
                        )
                        if reg:
                            local_regs.append(reg)
                    if brace_depth <= 0 or "};" in stripped:
                        in_init = False
                        current_struct = ""

            # Runtime assignments
            for line_num, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*"):
                    continue
                match = self.RUNTIME_ASSIGN.search(stripped)
                if not match:
                    continue
                prefix = match.group(1) or ""
                field_name = match.group(2)
                target = match.group(3)
                struct_type = self.OPS_FIELD_MAP.get(field_name)
                if struct_type and target.startswith("&"):
                    continue
                for stype, fields in KNOWN_OPS_STRUCTS.items():
                    if field_name in fields and fields[field_name] is not None:
                        if (re.match(r'^[a-zA-Z_]\w*$', target) and
                                target not in ("NULL", "true", "false", "0", "1", "THIS_MODULE")):
                            local_regs.append(OpsRegistration(
                                struct_type=stype, field_name=field_name,
                                target_function=target, source_file=rel_path,
                                line_number=line_num, instance_name=prefix,
                                is_static_init=False,
                            ))
                        break

            # --- Dispatches ---
            local_disps = self._scan_dispatch_lines(lines, rel_path)

            return local_regs, local_disps

        # Fan out across threads
        if not files:
            print("    No files to scan")
            return
        n_workers = min(os.cpu_count() or 4, len(files), 16)
        n_workers = max(n_workers, 1)
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = {pool.submit(_process_file, f): f for f in files}
            for future in as_completed(futures):
                try:
                    regs, disps = future.result()
                    self.registrations.extend(regs)
                    self.dispatches.extend(disps)
                    self._files_scanned += 1
                except Exception:
                    pass

        print(f"    Scanned {self._files_scanned} files")
        print(f"    Found {len(self.registrations)} registrations, "
              f"{len(self.dispatches)} dispatch sites")

        # Build registration index
        for reg in self.registrations:
            key = (reg.struct_type, reg.field_name)
            self._reg_index[key].append(reg)

    def _make_registration(
        self, struct_type, field_name, target, file_path, line_num, instance_name, is_static,
    ) -> OpsRegistration | None:
        """Create a registration if the field/target are valid (thread-safe helper)."""
        known_fields = self._known_fields.get(struct_type, set())
        if field_name not in known_fields:
            return None
        if target in ("NULL", "0", "THIS_MODULE", "true", "false"):
            return None
        if not re.match(r'^[a-zA-Z_]\w*$', target):
            return None
        return OpsRegistration(
            struct_type=struct_type, field_name=field_name,
            target_function=target, source_file=file_path,
            line_number=line_num, instance_name=instance_name,
            is_static_init=is_static,
        )

    def run(self, discover_new: bool = False) -> list[FptrEdge]:
        """Run the full function pointer resolution pipeline."""
        # Build fast enclosing-function index from ctags
        self._build_func_line_index()

        # Single-pass parallel scan (replaces separate scan_registrations + scan_dispatches)
        self._scan_all()
        edges = self.resolve()

        if discover_new:
            self.discover_ops_structs()

        return edges

    def save_edges(self, path: str) -> None:
        """Save resolved edges to JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = {
            "edges": [asdict(e) for e in self.resolved_edges],
            "stats": {
                "registrations": len(self.registrations),
                "dispatch_sites": len(self.dispatches),
                "resolved_edges": len(self.resolved_edges),
                "unique_targets": len(set(e.target_function for e in self.resolved_edges)),
                "unique_dispatchers": len(set(e.dispatch_function for e in self.resolved_edges)),
                "files_scanned": self._files_scanned,
            },
            "registrations_by_struct": {
                stype: len(regs) for (stype, _), regs in self._reg_index.items()
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved to {path}")

    def summary(self) -> dict:
        """Return summary statistics."""
        reg_by_type = defaultdict(int)
        for reg in self.registrations:
            reg_by_type[reg.struct_type] += 1

        dispatch_by_type = defaultdict(int)
        for d in self.dispatches:
            dispatch_by_type[d.struct_type] += 1

        return {
            "files_scanned": self._files_scanned,
            "total_registrations": len(self.registrations),
            "total_dispatches": len(self.dispatches),
            "resolved_edges": len(self.resolved_edges),
            "registrations_by_struct": dict(reg_by_type),
            "dispatches_by_struct": dict(dispatch_by_type),
        }


def main():
    parser = argparse.ArgumentParser(description="Resolve kernel function pointer dispatch tables")
    parser.add_argument("--kernel-path", required=True, help="Path to Linux kernel source tree")
    parser.add_argument("--output", default="data/fptr_edges.json", help="Output JSON path")
    parser.add_argument("--graph", help="Existing callgraph.json to integrate edges into")
    parser.add_argument("--subsystems", nargs="+", help="Subsystems to scan")
    parser.add_argument("--discover", action="store_true",
                       help="Discover new ops structs from headers")

    args = parser.parse_args()

    resolver = FunctionPointerResolver(
        kernel_path=args.kernel_path,
        subsystems=args.subsystems,
    )

    edges = resolver.run(discover_new=args.discover)
    resolver.save_edges(args.output)

    # If existing graph provided, integrate
    if args.graph:
        print(f"\n[*] Loading existing graph from {args.graph}")
        kg = KernelGraph.load(args.graph)
        print(f"    Before: {kg.num_nodes} nodes, {kg.num_edges} edges")

        added = resolver.integrate_into_graph(kg)

        print(f"    After: {kg.num_nodes} nodes, {kg.num_edges} edges")

        out_graph = args.graph.replace(".json", "_with_fptrs.json")
        kg.save(out_graph)
        print(f"[+] Enriched graph saved to {out_graph}")

    print(f"\n[+] Summary:")
    print(json.dumps(resolver.summary(), indent=2))


if __name__ == "__main__":
    main()
