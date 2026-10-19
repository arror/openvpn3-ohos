#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build a disposable GPL OpenVPN 2.6 server, never linked into the app.
The small test-only macOS socketpair adapter substitutes for a privileged TUN.
Compression/TLS code remains upstream. Source and build stay outside the repo.
"""
import argparse, hashlib, os, subprocess, tarfile, urllib.request
from pathlib import Path
VERSION = '2.6.14'
SHA256 = '9eb6a6618352f9e7b771a9d38ae1631b5edfeed6d40233e243e602ddf2195e7a'
ADAPTER = r'''
    /* ARKOVPN_TEST_UNIX_TUN: test-only socket transport, raw IP packets. */
    if (dev_node && strncmp(dev_node, "unix:", 5) == 0)
    {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0)
            msg(M_FATAL | M_ERRNO, "test socketpair failed");
        pid_t child = fork();
        if (child < 0) msg(M_FATAL | M_ERRNO, "test peer fork failed");
        if (child == 0)
        {
            char fd[32];
            close(pair[0]);
            snprintf(fd, sizeof(fd), "%d", pair[1]);
            setenv("TUNTAP_SOCKET_FD", fd, 1);
            execl(dev_node + 5, dev_node + 5, (char *)NULL);
            _exit(127);
        }
        close(pair[1]);
        tt->fd = pair[0];
        tt->actual_name = string_alloc("unix-test", NULL);
        set_nonblock(tt->fd);
        return;
    }
'''
def build(work):
    work.mkdir(parents=True, exist_ok=True)
    archive = work / f'openvpn-{VERSION}.tar.gz'
    if not archive.exists():
        urllib.request.urlretrieve(f'https://swupdate.openvpn.org/community/releases/openvpn-{VERSION}.tar.gz', archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError('COMPRESSION_SERVER_ARCHIVE_CHECKSUM')
    source = work / f'openvpn-{VERSION}'
    if not source.exists():
        with tarfile.open(archive) as tar:
            if hasattr(tarfile, 'data_filter'):
                tar.extractall(work, filter='data')
            else:
                members = tar.getmembers()
                for member in members:
                    if Path(member.name).is_absolute() or '..' in Path(member.name).parts or not (member.isfile() or member.isdir()):
                        raise RuntimeError('UNSAFE_COMPRESSION_SERVER_ARCHIVE')
                tar.extractall(work, members=members)
    tun = source / 'src/openvpn/tun.c'
    content = tun.read_text()
    content = content.replace(ADAPTER, '')
    start = content.rindex('#elif defined(TARGET_DARWIN)')
    target = content.index('open_tun(const char *dev,', start)
    pos = content.index('{', target) + 1
    tun.write_text(content[:pos] + ADAPTER + content[pos:])
    env = os.environ.copy()
    prefixes = [subprocess.check_output(['brew', '--prefix', n], text=True).strip() for n in ['openssl@3','lzo','lz4']]
    env['PKG_CONFIG_PATH'] = ':'.join(p+'/lib/pkgconfig' for p in prefixes)
    env['CPPFLAGS'] = ' '.join('-I'+p+'/include' for p in prefixes)
    env['LDFLAGS'] = ' '.join('-L'+p+'/lib' for p in prefixes)
    subprocess.run(['./configure', '--disable-plugin-auth-pam', '--disable-pkcs11', '--disable-unit-tests', '--disable-dependency-tracking'], cwd=source, env=env, check=True)
    subprocess.run(['./config.status','config.h'], cwd=source, env=env, check=True)
    subprocess.run(['make','-j',str(min(os.cpu_count() or 2,8))], cwd=source, env=env, check=True)
    print(source/'src/openvpn/openvpn', flush=True)
if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True)
    build(parser.parse_args().work)
