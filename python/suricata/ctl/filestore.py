# Copyright (C) 2018 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import sys
import os
import os.path
import time
import re
import glob
import logging

logger = logging.getLogger("filestore")

class InvalidAgeFormatError(Exception):
    pass

def register_args(parser):

    parsers = parser.add_subparsers()

    prune_parser = parsers.add_parser("prune")
    prune_parser.add_argument("-d", "--directory", help="filestore directory")
    prune_parser.add_argument("--age", help="prune files older than age")
    prune_parser.add_argument(
        "-n", "--dry-run", action="store_true", default=False,
        help="only print what would happen");
    prune_parser.add_argument(
        "-v", "--verbose", action="store_true",
        default=False, help="increase verbosity")
    prune_parser.add_argument(
        "-q", "--quiet", action="store_true", default=False,
        help="be quiet, log warnings and errors only")
    prune_parser.set_defaults(func=prune)

def is_fileinfo(path):
    return path.endswith(".json")

def parse_age(age):
    m = re.match("(\d+)\s*(\w+)", age)
    if not m:
        raise InvalidAgeFormatError(age)
    val = int(m.group(1))
    unit = m.group(2)

    if unit == "s":
        return val
    elif unit == "m":
        return val * 60
    elif unit == "h":
        return val * 60 * 60
    elif unit == "d":
        return val * 60 * 60 * 24
    else:
        raise InvalidAgeFormatError("bad unit: %s" % (unit))

def get_filesize(path):
    return os.stat(path).st_size

def remove_file(path, dry_run):
    size = 0
    size += get_filesize(path)
    if not dry_run:
        os.unlink(path)
    return size

def prune(args):

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.quiet:
        logger.setLevel(logging.WARNING)

    if not args.directory:
        print(
            "error: the filestore directory must be provided with --directory",
            file=sys.stderr)
        return 1
    
    if not args.age:
        print("error: no age provided, nothing to do", file=sys.stderr)
        return 1

    age = parse_age(args.age)
    now = time.time()
    size = 0
    count = 0

    for dirpath, dirnames, filenames in os.walk(args.directory, topdown=True):

        # Do not go into the tmp directory.
        if "tmp" in dirnames:
            dirnames.remove("tmp")

        for filename in filenames:
            path = os.path.join(dirpath, filename)
            mtime = os.path.getmtime(path)
            this_age = now - mtime
            if this_age > age:
                logger.debug("Deleting %s; age=%ds" % (path, this_age))
                size += remove_file(path, args.dry_run)
                count += 1

    logger.info("Removed %d files; %d bytes." % (count, size))
