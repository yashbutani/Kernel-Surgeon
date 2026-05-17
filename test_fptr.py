#!/usr/bin/env python3
"""
Test the function pointer resolver against realistic kernel driver source.

Creates a fake kernel tree with:
- A character device driver (file_operations)
- A network driver (net_device_ops, ethtool_ops)
- A filesystem (inode_operations, super_operations, address_space_operations)
- VFS dispatch code (the core calling through f_op->read etc.)
- A block driver (block_device_operations)

Then validates that the resolver correctly:
1. Finds all static initializer registrations
2. Finds dispatch call sites
3. Connects dispatches to concrete implementations
4. Integrates into KernelGraph with correct edge types
"""

import json
import os
import sys
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fptr_resolver import FunctionPointerResolver
from kernel_graph import KernelGraph, EdgeType


def create_fake_kernel_tree(root: Path) -> None:
    """Create a minimal but realistic kernel source tree."""

    # ================================================================
    # drivers/char/my_chardev.c — Character device driver
    # ================================================================
    chardev_dir = root / "drivers" / "char"
    chardev_dir.mkdir(parents=True)
    (chardev_dir / "my_chardev.c").write_text("""\
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>

static int my_chardev_open(struct inode *inode, struct file *filp)
{
    struct my_device *dev;
    dev = container_of(inode->i_cdev, struct my_device, cdev);
    filp->private_data = dev;
    return 0;
}

static ssize_t my_chardev_read(struct file *filp, char __user *buf,
                                size_t count, loff_t *pos)
{
    struct my_device *dev = filp->private_data;
    char *kbuf;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    /* BUG: no bounds check on count before copy */
    memcpy(kbuf, dev->buffer + *pos, count);

    if (copy_to_user(buf, kbuf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    *pos += count;
    return count;
}

static ssize_t my_chardev_write(struct file *filp, const char __user *buf,
                                 size_t count, loff_t *pos)
{
    struct my_device *dev = filp->private_data;
    if (copy_from_user(dev->buffer + *pos, buf, count))
        return -EFAULT;
    *pos += count;
    return count;
}

static long my_chardev_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    struct my_device *dev = filp->private_data;

    switch (cmd) {
    case MY_IOCTL_RESET:
        memset(dev->buffer, 0, dev->buf_size);
        return 0;
    case MY_IOCTL_GETSIZE:
        return put_user(dev->buf_size, (unsigned long __user *)arg);
    default:
        return -ENOTTY;
    }
}

static int my_chardev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct my_device *dev = filp->private_data;
    return remap_pfn_range(vma, vma->vm_start,
                           virt_to_phys(dev->buffer) >> PAGE_SHIFT,
                           vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static int my_chardev_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static const struct file_operations my_chardev_fops = {
    .owner = THIS_MODULE,
    .open = my_chardev_open,
    .read = my_chardev_read,
    .write = my_chardev_write,
    .unlocked_ioctl = my_chardev_ioctl,
    .mmap = my_chardev_mmap,
    .release = my_chardev_release,
};
""")

    # ================================================================
    # drivers/net/my_netdev.c — Network driver
    # ================================================================
    netdev_dir = root / "drivers" / "net"
    netdev_dir.mkdir(parents=True)
    (netdev_dir / "my_netdev.c").write_text("""\
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>

static int my_net_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int my_net_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static netdev_tx_t my_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct my_adapter *adapter = netdev_priv(dev);

    /* BUG: no check on skb->len before DMA mapping */
    dma_addr_t dma = dma_map_single(&adapter->pdev->dev, skb->data,
                                     skb->len, DMA_TO_DEVICE);
    adapter->tx_ring[adapter->tx_head].addr = dma;
    adapter->tx_ring[adapter->tx_head].len = skb->len;
    adapter->tx_head = (adapter->tx_head + 1) % TX_RING_SIZE;

    return NETDEV_TX_OK;
}

static void my_net_set_rx_mode(struct net_device *dev)
{
    struct my_adapter *adapter = netdev_priv(dev);
    /* Configure multicast filters */
}

static int my_net_change_mtu(struct net_device *dev, int new_mtu)
{
    if (new_mtu < 68 || new_mtu > 9000)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

static int my_net_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    return -EOPNOTSUPP;
}

static const struct net_device_ops my_netdev_ops = {
    .ndo_open = my_net_open,
    .ndo_stop = my_net_stop,
    .ndo_start_xmit = my_net_xmit,
    .ndo_set_rx_mode = my_net_set_rx_mode,
    .ndo_change_mtu = my_net_change_mtu,
    .ndo_eth_ioctl = my_net_ioctl,
};

static void my_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, "my_netdev", sizeof(info->driver));
}

static u32 my_get_link(struct net_device *dev)
{
    struct my_adapter *adapter = netdev_priv(dev);
    return adapter->link_up;
}

static const struct ethtool_ops my_ethtool_ops = {
    .get_drvinfo = my_get_drvinfo,
    .get_link = my_get_link,
};
""")

    # ================================================================
    # fs/myfs/inode.c — Filesystem
    # ================================================================
    fs_dir = root / "fs" / "myfs"
    fs_dir.mkdir(parents=True)
    (fs_dir / "inode.c").write_text("""\
#include <linux/fs.h>
#include <linux/pagemap.h>

static struct dentry *myfs_lookup(struct inode *dir, struct dentry *dentry,
                                   unsigned int flags)
{
    struct inode *inode = NULL;
    inode = myfs_iget(dir->i_sb, dentry);
    return d_splice_alias(inode, dentry);
}

static int myfs_create(struct mnt_idmap *idmap, struct inode *dir,
                        struct dentry *dentry, umode_t mode, bool excl)
{
    struct inode *inode = myfs_new_inode(dir, mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    d_instantiate(dentry, inode);
    return 0;
}

static int myfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                       struct dentry *dentry, umode_t mode)
{
    return myfs_create(idmap, dir, dentry, mode | S_IFDIR, false);
}

static int myfs_permission(struct mnt_idmap *idmap, struct inode *inode,
                            int mask)
{
    /* BUG: always returns 0, bypassing permission checks */
    return 0;
}

static const struct inode_operations myfs_dir_inode_ops = {
    .lookup = myfs_lookup,
    .create = myfs_create,
    .mkdir = myfs_mkdir,
    .permission = myfs_permission,
};

static struct inode *myfs_alloc_inode(struct super_block *sb)
{
    struct myfs_inode_info *info;
    info = kmem_cache_alloc(myfs_inode_cachep, GFP_KERNEL);
    if (!info)
        return NULL;
    return &info->vfs_inode;
}

static void myfs_destroy_inode(struct inode *inode)
{
    kmem_cache_free(myfs_inode_cachep, MYFS_I(inode));
}

static int myfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    buf->f_type = MYFS_MAGIC;
    buf->f_bsize = PAGE_SIZE;
    return 0;
}

static const struct super_operations myfs_super_ops = {
    .alloc_inode = myfs_alloc_inode,
    .destroy_inode = myfs_destroy_inode,
    .statfs = myfs_statfs,
};
""")

    # ================================================================
    # fs/read_write.c — VFS dispatch (calls through f_op->read etc.)
    # ================================================================
    (root / "fs").mkdir(exist_ok=True)
    (root / "fs" / "read_write.c").write_text("""\
#include <linux/fs.h>
#include <linux/uaccess.h>

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_READ))
        return -EBADF;

    if (unlikely(!access_ok(buf, count)))
        return -EFAULT;

    ret = file->f_op->read(file, buf, count, pos);
    return ret;
}

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_WRITE))
        return -EBADF;

    ret = file->f_op->write(file, buf, count, pos);
    return ret;
}

long vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    if (!filp->f_op->unlocked_ioctl)
        return -ENOTTY;
    return filp->f_op->unlocked_ioctl(filp, cmd, arg);
}

int vfs_open(const struct path *path, struct file *file)
{
    struct inode *inode = path->dentry->d_inode;
    if (file->f_op->open)
        return file->f_op->open(inode, file);
    return 0;
}
""")

    # ================================================================
    # fs/namei.c — VFS inode dispatch
    # ================================================================
    (root / "fs" / "namei.c").write_text("""\
#include <linux/fs.h>
#include <linux/namei.h>

static struct dentry *lookup_real(struct inode *dir, struct dentry *dentry,
                                   unsigned int flags)
{
    struct dentry *res;

    if (!dir->i_op->lookup)
        return ERR_PTR(-ENOTDIR);

    res = dir->i_op->lookup(dir, dentry, flags);
    return res;
}

int may_create(struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *child)
{
    int error = dir->i_op->permission(idmap, dir, MAY_WRITE | MAY_EXEC);
    if (error)
        return error;
    return 0;
}

int vfs_create(struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode, bool excl)
{
    int error = may_create(idmap, dir, dentry);
    if (error)
        return error;
    return dir->i_op->create(idmap, dir, dentry, mode, excl);
}

int vfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
              struct dentry *dentry, umode_t mode)
{
    int error = may_create(idmap, dir, dentry);
    if (error)
        return error;
    return dir->i_op->mkdir(idmap, dir, dentry, mode);
}
""")

    # ================================================================
    # net/core/dev.c — Network dispatch
    # ================================================================
    net_dir = root / "net" / "core"
    net_dir.mkdir(parents=True)
    (net_dir / "dev.c").write_text("""\
#include <linux/netdevice.h>

int dev_open(struct net_device *dev, struct netlink_ext_ack *extack)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    int ret;

    if (ops->ndo_open)
        ret = ops->ndo_open(dev);
    return ret;
}

static netdev_tx_t dev_hard_start_xmit(struct sk_buff *skb,
                                         struct net_device *dev)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    return ops->netdev_ops->ndo_start_xmit(skb, dev);
}

int dev_change_mtu(struct net_device *dev, int new_mtu)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    if (ops->ndo_change_mtu)
        return ops->netdev_ops->ndo_change_mtu(dev, new_mtu);
    dev->mtu = new_mtu;
    return 0;
}

void dev_set_rx_mode(struct net_device *dev)
{
    if (dev->netdev_ops->ndo_set_rx_mode)
        dev->netdev_ops->ndo_set_rx_mode(dev);
}
""")

    # ================================================================
    # drivers/block/my_blkdev.c — Block device driver
    # ================================================================
    blk_dir = root / "drivers" / "block"
    blk_dir.mkdir(parents=True)
    (blk_dir / "my_blkdev.c").write_text("""\
#include <linux/blkdev.h>

static int my_blk_open(struct gendisk *disk, blk_mode_t mode)
{
    return 0;
}

static void my_blk_release(struct gendisk *disk)
{
}

static int my_blk_ioctl(struct block_device *bdev, blk_mode_t mode,
                         unsigned cmd, unsigned long arg)
{
    switch (cmd) {
    case MY_BLK_IOCTL:
        /* BUG: user pointer used directly without copy_from_user */
        memcpy(bdev->bd_disk->private_data, (void __user *)arg, 256);
        return 0;
    default:
        return -ENOTTY;
    }
}

static void my_blk_submit_bio(struct bio *bio)
{
    bio_endio(bio);
}

static const struct block_device_operations my_blk_fops = {
    .owner = THIS_MODULE,
    .open = my_blk_open,
    .release = my_blk_release,
    .ioctl = my_blk_ioctl,
    .submit_bio = my_blk_submit_bio,
};
""")


def run_test():
    """Run the function pointer resolver on the fake kernel tree."""
    # Create temp kernel tree
    tmpdir = tempfile.mkdtemp(prefix="kernelgraph_test_")
    root = Path(tmpdir)

    try:
        print("=" * 70)
        print("FUNCTION POINTER RESOLVER TEST")
        print("=" * 70)

        print(f"\n[1] Creating synthetic kernel tree in {root}...")
        create_fake_kernel_tree(root)

        # Count source files created
        c_files = list(root.rglob("*.c"))
        print(f"    Created {len(c_files)} source files")

        # Run resolver
        print(f"\n[2] Running function pointer resolver...")
        resolver = FunctionPointerResolver(
            kernel_path=str(root),
            subsystems=["drivers/", "fs/", "net/"],
        )
        edges = resolver.run(discover_new=False)

        # ============================================================
        # VALIDATION
        # ============================================================
        print(f"\n{'='*70}")
        print("VALIDATION RESULTS")
        print(f"{'='*70}")

        # Check registrations were found
        reg_targets = {r.target_function for r in resolver.registrations}
        expected_registrations = {
            # Chardev
            "my_chardev_open", "my_chardev_read", "my_chardev_write",
            "my_chardev_ioctl", "my_chardev_mmap", "my_chardev_release",
            # Netdev
            "my_net_open", "my_net_stop", "my_net_xmit",
            "my_net_set_rx_mode", "my_net_change_mtu", "my_net_ioctl",
            # Ethtool
            "my_get_drvinfo", "my_get_link",
            # Filesystem inode ops
            "myfs_lookup", "myfs_create", "myfs_mkdir", "myfs_permission",
            # Filesystem super ops
            "myfs_alloc_inode", "myfs_destroy_inode", "myfs_statfs",
            # Block device
            "my_blk_open", "my_blk_release", "my_blk_ioctl", "my_blk_submit_bio",
        }

        print(f"\n  Registration detection:")
        found_regs = reg_targets & expected_registrations
        missed_regs = expected_registrations - reg_targets
        print(f"    Expected: {len(expected_registrations)}")
        print(f"    Found:    {len(found_regs)}")
        print(f"    Missed:   {len(missed_regs)}")
        if missed_regs:
            for m in sorted(missed_regs):
                print(f"      ✗ {m}")
        for r in sorted(found_regs):
            print(f"      ✓ {r}")

        # Check dispatch sites were found
        dispatch_methods = {(d.struct_type, d.field_name) for d in resolver.dispatches}
        expected_dispatches = {
            ("file_operations", "read"),
            ("file_operations", "write"),
            ("file_operations", "unlocked_ioctl"),
            ("file_operations", "open"),
            ("inode_operations", "lookup"),
            ("inode_operations", "permission"),
            ("inode_operations", "create"),
            ("inode_operations", "mkdir"),
        }

        print(f"\n  Dispatch site detection:")
        found_dispatches = dispatch_methods & expected_dispatches
        missed_dispatches = expected_dispatches - dispatch_methods
        print(f"    Expected: {len(expected_dispatches)}")
        print(f"    Found:    {len(found_dispatches)}")
        print(f"    Missed:   {len(missed_dispatches)}")
        for d in sorted(found_dispatches):
            print(f"      ✓ {d[0]}.{d[1]}")
        for d in sorted(missed_dispatches):
            print(f"      ✗ {d[0]}.{d[1]}")

        # Check resolved edges
        print(f"\n  Resolved edges:")
        print(f"    Total: {len(edges)}")

        # Key edges we want to see
        edge_pairs = {(e.dispatch_function, e.target_function) for e in edges}
        key_edges = [
            ("vfs_read", "my_chardev_read", "VFS read dispatches to chardev"),
            ("vfs_write", "my_chardev_write", "VFS write dispatches to chardev"),
            ("vfs_ioctl", "my_chardev_ioctl", "VFS ioctl dispatches to chardev"),
            ("vfs_open", "my_chardev_open", "VFS open dispatches to chardev"),
            ("lookup_real", "myfs_lookup", "VFS lookup dispatches to filesystem"),
            ("may_create", "myfs_permission", "VFS permission check dispatches to fs"),
            ("vfs_create", "myfs_create", "VFS create dispatches to filesystem"),
            ("vfs_mkdir", "myfs_mkdir", "VFS mkdir dispatches to filesystem"),
        ]

        for dispatch, target, desc in key_edges:
            found = (dispatch, target) in edge_pairs
            icon = "✓" if found else "✗"
            status = "PASS" if found else "FAIL"
            print(f"    {icon} [{status}] {desc}: {dispatch} → {target}")

        # Integration test
        print(f"\n[3] Integration test — adding to KernelGraph...")
        kg = KernelGraph()

        # Add some base nodes
        kg.add_function("vfs_read", "fs/read_write.c")
        kg.add_function("vfs_write", "fs/read_write.c")
        kg.add_function("vfs_ioctl", "fs/read_write.c")
        kg.add_function("vfs_open", "fs/read_write.c")
        kg.add_function("sys_read", "kernel/sys.c")
        kg.add_call_edge(
            "kernel/sys.c::sys_read", "fs/read_write.c::vfs_read", EdgeType.CALLS
        )

        before_edges = kg.num_edges
        added = resolver.integrate_into_graph(kg)
        after_edges = kg.num_edges

        print(f"    Edges before: {before_edges}")
        print(f"    Edges after:  {after_edges}")
        print(f"    Fptr edges added: {added}")

        # Verify we can now trace: sys_read → vfs_read →(fptr)→ my_chardev_read
        read_ids = kg.lookup_function("vfs_read")
        chardev_read_ids = kg.lookup_function("my_chardev_read")
        if read_ids and chardev_read_ids:
            successors = set(kg.graph.successors(read_ids[0]))
            if chardev_read_ids[0] in successors:
                print(f"    ✓ Can trace: vfs_read →(fptr)→ my_chardev_read")
            else:
                print(f"    ✗ Missing: vfs_read →(fptr)→ my_chardev_read")

        # Check edge type is INDIRECT_CALL
        if read_ids and chardev_read_ids:
            for _, _, _, data in kg.graph.edges(read_ids[0], data=True, keys=True):
                if data.get("edge_type") == EdgeType.INDIRECT_CALL.value:
                    print(f"    ✓ Edge correctly typed as INDIRECT_CALL")
                    break

        # Save
        os.makedirs("data", exist_ok=True)
        resolver.save_edges("data/test_fptr_edges.json")
        kg.save("data/test_graph_with_fptrs.json")

        print(f"\n{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        print(json.dumps(resolver.summary(), indent=2))

        reg_pass = len(missed_regs) <= 2  # allow some misses
        dispatch_pass = len(found_dispatches) >= 4
        edge_pass = len(edges) > 0

        if reg_pass and dispatch_pass and edge_pass:
            print(f"\n  ★ Function pointer resolution working correctly!")
        else:
            print(f"\n  ⚠ Some issues detected — check output above")

    finally:
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    run_test()
