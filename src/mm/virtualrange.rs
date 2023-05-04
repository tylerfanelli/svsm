// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024};

use super::{
    SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M,
    SVSM_PERCPU_TEMP_END_4K,
};

pub const VIRT_ALIGN_4K: usize = PAGE_SHIFT - 12;
pub const VIRT_ALIGN_2M: usize = PAGE_SHIFT_2M - 12;

pub struct VirtualRange {
    start_virt: VirtAddr,
    page_count: usize,
    bits: BitmapAllocator1024,
}

impl VirtualRange {
    pub const CAPACITY: usize = BitmapAllocator1024::CAPACITY;

    pub const fn new() -> VirtualRange {
        VirtualRange {
            start_virt: VirtAddr::null(),
            page_count: 0,
            bits: BitmapAllocator1024::new(),
        }
    }

    pub fn init(&mut self, start_virt: VirtAddr, page_count: usize) {
        self.start_virt = start_virt;
        self.page_count = page_count;
        self.bits.set(0, page_count, false);
    }

    pub fn alloc(
        self: &mut Self,
        page_count: usize,
        alignment: usize,
    ) -> Result<VirtAddr, SvsmError> {
        // Always reserve an extra page to leave a guard between virtual memory allocations
        match self.bits.alloc(page_count + 1, alignment) {
            Some(offset) => Ok(self.start_virt.offset(offset << PAGE_SHIFT)),
            None => Err(SvsmError::Mem),
        }
    }

    pub fn free(self: &mut Self, vaddr: VirtAddr, page_count: usize) {
        let offset = (vaddr - self.start_virt) >> PAGE_SHIFT;
        // Add 1 to the page count for the VM guard
        self.bits.free(offset, page_count + 1);
    }

    pub fn used_pages(&self) -> usize {
        self.bits.used()
    }
}

pub fn virt_log_usage() {
    let page_count4k = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
    let page_count2m = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
    let unused_cap_4k = BitmapAllocator1024::CAPACITY - page_count4k;
    let unused_cap_2m = BitmapAllocator1024::CAPACITY - page_count2m;

    log::info!(
        "[CPU {}] Virtual memory pages used: {} * 4K, {} * 2M",
        this_cpu().get_apic_id(),
        this_cpu().vrange_4k.used_pages() - unused_cap_4k,
        this_cpu().vrange_2m.used_pages() - unused_cap_2m
    );
}

pub fn virt_alloc_range_4k(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 4K page
    if (size_bytes & (PAGE_SIZE - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT;
    this_cpu_mut().vrange_4k.alloc(page_count, alignment)
}

pub fn virt_free_range_4k(vaddr: VirtAddr, size_bytes: usize) {
    this_cpu_mut()
        .vrange_4k
        .free(vaddr, size_bytes >> PAGE_SHIFT);
}

pub fn virt_alloc_range_2m(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 2M page
    if (size_bytes & (PAGE_SIZE_2M - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT_2M;
    this_cpu_mut().vrange_2m.alloc(page_count, alignment)
}

pub fn virt_free_range_2m(vaddr: VirtAddr, size_bytes: usize) {
    this_cpu_mut()
        .vrange_2m
        .free(vaddr, size_bytes >> PAGE_SHIFT_2M);
}