/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

extern crate libc;
use std;

#[repr(C)]
pub struct AppLayerGetTxIterTuple {
    tx_ptr: *mut libc::c_void,
    tx_id: u64,
    has_next: bool,
}

impl AppLayerGetTxIterTuple {
    pub fn with_values(tx_ptr: *mut libc::c_void, tx_id: u64, has_next: bool) -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: tx_ptr, tx_id: tx_id, has_next: has_next,
        }
    }
    pub fn not_found() -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: std::ptr::null_mut(), tx_id: 0, has_next: false,
        }
    }
}

/// LoggerFlags tracks which loggers have already been executed.
#[derive(Debug)]
pub struct LoggerFlags {
    flags: u32,
}

impl LoggerFlags {

    pub fn new() -> LoggerFlags {
        return LoggerFlags{
            flags: 0,
        }
    }

    pub fn get(&self) -> u32 {
        self.flags
    }

    pub fn set(&mut self, bits: u32) {
        self.flags = bits;
    }

}
