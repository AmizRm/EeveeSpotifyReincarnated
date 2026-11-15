"""Linux stand-ins for the Darwin-only steps of the Pixie build.

The patching itself is pure python and already portable. What is not portable is
the toolchain around it: codesign, xcrun clang against the iPhoneOS SDK, and
dyld_info. On linux those come from a Theos install instead:

  $THEOS/toolchain/linux/iphone/bin   ld64, ldid, nm, otool
  $THEOS/sdks/iPhoneOS*.sdk           headers and .tbd stubs

Theos' own clang is too old to parse a current SDK, so sources are compiled with
a newer system clang and only the link is driven through the Theos one. Override
any of it with PIXIE_IOS_SDK, PIXIE_CC, PIXIE_TOOLCHAIN or PIXIE_COMPILER_RT.
"""
import os
import struct
import subprocess
import sys
from pathlib import Path

DARWIN = sys.platform == 'darwin'


def theos_root():
    return Path(os.environ.get('THEOS', '/opt/theos'))


def toolchain_bin():
    override = os.environ.get('PIXIE_TOOLCHAIN')
    if override:
        return Path(override)
    return theos_root() / 'toolchain' / 'linux' / 'iphone' / 'bin'


def tool(name):
    path = toolchain_bin() / name
    if not path.exists():
        raise RuntimeError('missing {} - is Theos installed at {}?'.format(path, theos_root()))
    return str(path)


def sdk_path():
    override = os.environ.get('PIXIE_IOS_SDK')
    if override:
        return override
    found = sorted((theos_root() / 'sdks').glob('iPhoneOS*.sdk'))
    if not found:
        raise RuntimeError('no iPhoneOS*.sdk under {}/sdks'.format(theos_root()))
    return str(found[-1])


def subframeworks(sdk):
    # UIKit's own headers include <UIUtilities/UIDefines.h>, which lives here and
    # is not on clang's default framework search path.
    return str(Path(sdk) / 'System' / 'Library' / 'SubFrameworks')


def compiler():
    return os.environ.get('PIXIE_CC', 'clang')


def compiler_rt():
    """Apple's builtins archive, which provides __isOSVersionAtLeast."""
    override = os.environ.get('PIXIE_COMPILER_RT')
    if override:
        return override
    for base in (theos_root() / 'vendor' / 'lib', theos_root() / 'lib', Path('/usr/local/lib')):
        candidate = base / 'libclang_rt.ios.a'
        if candidate.exists():
            return str(candidate)
    return None


def adhoc_sign(path, entitlements=None):
    command = [tool('ldid')]
    command.append('-S{}'.format(entitlements) if entitlements else '-S')
    command.append(str(path))
    subprocess.run(command, check=True)


def validate(path):
    """Stand-in for `dyld_info -validate_only`.

    There is no linux equivalent, so this only confirms the file is still a thin
    arm64 Mach-O that otool can walk - enough to catch a truncated or corrupted
    write, not a substitute for dyld's own checks.
    """
    data = Path(path).read_bytes()
    if len(data) < 4 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise RuntimeError('{} is not a thin little-endian 64-bit Mach-O'.format(path))
    subprocess.run([tool('otool'), '-l', str(path)], check=True, stdout=subprocess.DEVNULL)


DYLIB_COMMANDS = {0xC, 0x18, 0x80000018, 0x8000001F, 0x80000023}
CHAINED_FIXUPS = 0x80000034


def imports_listing(data):
    """A `dyld_info -imports` style listing, read from the chained-fixups table.

    This is the table dyld actually binds through, and the one the import patch
    rewrites. nm reads the classic symbol table instead, whose library ordinals
    the patch deliberately leaves alone - so nm still names the original
    provider and is not a substitute here.
    """
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<8I', data)
    if magic != 0xFEEDFACF:
        raise RuntimeError('expected a thin little-endian 64-bit Mach-O')
    cursor, libraries, fixups = 32, [], None
    for _ in range(ncmds):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > 32 + sizeofcmds:
            raise RuntimeError('malformed load commands')
        if command in DYLIB_COMMANDS:
            name_offset = struct.unpack_from('<I', data, cursor + 8)[0]
            libraries.append(data[cursor + name_offset:cursor + size].split(b'\0')[0].decode())
        elif command == CHAINED_FIXUPS:
            fixups = struct.unpack_from('<II', data, cursor + 8)
        cursor += size
    if fixups is None:
        raise RuntimeError('no chained-fixups load command')
    base, fixup_size = fixups
    version, starts, table, symbols, count, import_format, symbol_format = struct.unpack_from('<7I', data, base)
    if version != 0 or symbol_format != 0 or import_format not in (1, 2, 3):
        raise RuntimeError('unsupported chained imports encoding')
    stride = {1: 4, 2: 8, 3: 16}[import_format]
    mask = 65535 if import_format == 3 else 255
    shift = 32 if import_format == 3 else 9
    packing = '<Q' if import_format == 3 else '<I'
    lines = []
    for index in range(count):
        offset = base + table + index * stride
        if offset + stride > base + fixup_size:
            raise RuntimeError('imports table extends beyond fixups')
        record = struct.unpack_from(packing, data, offset)[0]
        ordinal = record & mask
        start = base + symbols + (record >> shift)
        name = data[start:data.index(b'\0', start, base + fixup_size)].decode()
        provider = libraries[ordinal - 1] if 1 <= ordinal <= len(libraries) else 'ordinal {}'.format(ordinal)
        lines.append('{} (from {})'.format(name, provider))
    return '\n'.join(lines) + '\n'


def assemble(source, obj):
    """clang -c on a pure .S file.

    No SDK headers are involved, so -isysroot is only passed on darwin where
    xcrun supplies it anyway. The caller then reads __text out of the object.
    """
    if DARWIN:
        sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        command = ['xcrun', 'clang', '-c', '-arch', 'arm64', '-target', 'arm64-apple-ios15.0',
                   '-isysroot', sdk, str(source), '-o', str(obj)]
    else:
        command = [compiler(), '-c', '-arch', 'arm64', '-target', 'arm64-apple-ios15.0',
                   str(source), '-o', str(obj)]
    subprocess.run(command, check=True)
