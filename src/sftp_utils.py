import io
import os
import stat
import paramiko
from datetime import datetime, timezone


def _get_sftp_client(host):
    transport = paramiko.Transport((host.hostname, host.port))
    transport.set_keepalive(30)

    if host.auth_type == 'password':
        transport.connect(username=host.username, password=host.password)
    else:
        pkey = None
        passphrase = host.passphrase or None
        for kc in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
            try:
                pkey = kc.from_private_key(io.StringIO(host.ssh_key), password=passphrase)
                break
            except Exception:
                continue
        if pkey is None:
            raise ValueError("SSH Key ungültig")
        transport.connect(username=host.username, pkey=pkey)

    sftp = paramiko.SFTPClient.from_transport(transport)
    return sftp, transport


def list_directory(host, path='/'):
    sftp, transport = _get_sftp_client(host)
    try:
        entries = []
        for attr in sftp.listdir_attr(path):
            is_dir = stat.S_ISDIR(attr.st_mode) if attr.st_mode else False
            is_link = stat.S_ISLNK(attr.st_mode) if attr.st_mode else False
            entries.append({
                'name': attr.filename,
                'path': os.path.join(path, attr.filename).replace('\\', '/'),
                'size': attr.st_size or 0,
                'is_dir': is_dir,
                'is_link': is_link,
                'permissions': oct(attr.st_mode & 0o777) if attr.st_mode else '0000',
                'modified': datetime.fromtimestamp(attr.st_mtime, tz=timezone.utc).isoformat() if attr.st_mtime else '',
                'uid': attr.st_uid,
                'gid': attr.st_gid,
            })
        entries.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return entries
    finally:
        sftp.close()
        transport.close()


def download_file(host, remote_path):
    sftp, transport = _get_sftp_client(host)
    try:
        buf = io.BytesIO()
        sftp.getfo(remote_path, buf)
        buf.seek(0)
        filename = os.path.basename(remote_path)
        return buf.read(), filename
    finally:
        sftp.close()
        transport.close()


def upload_file(host, remote_path, file_data, filename):
    sftp, transport = _get_sftp_client(host)
    try:
        full_path = os.path.join(remote_path, filename).replace('\\', '/')
        buf = io.BytesIO(file_data)
        sftp.putfo(buf, full_path)
        return full_path
    finally:
        sftp.close()
        transport.close()


def delete_remote(host, remote_path, is_dir=False):
    sftp, transport = _get_sftp_client(host)
    try:
        if is_dir:
            sftp.rmdir(remote_path)
        else:
            sftp.remove(remote_path)
    finally:
        sftp.close()
        transport.close()


def mkdir_remote(host, remote_path):
    sftp, transport = _get_sftp_client(host)
    try:
        sftp.mkdir(remote_path)
    finally:
        sftp.close()
        transport.close()


def rename_remote(host, old_path, new_path):
    sftp, transport = _get_sftp_client(host)
    try:
        sftp.rename(old_path, new_path)
    finally:
        sftp.close()
        transport.close()


def get_file_stat(host, remote_path):
    sftp, transport = _get_sftp_client(host)
    try:
        attr = sftp.stat(remote_path)
        return {
            'size': attr.st_size,
            'permissions': oct(attr.st_mode & 0o777) if attr.st_mode else '0000',
            'modified': datetime.fromtimestamp(attr.st_mtime, tz=timezone.utc).isoformat() if attr.st_mtime else '',
            'is_dir': stat.S_ISDIR(attr.st_mode) if attr.st_mode else False,
        }
    finally:
        sftp.close()
        transport.close()