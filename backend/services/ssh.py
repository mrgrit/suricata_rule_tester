# backend/services/ssh.py
import paramiko, os

def _load_pkey(path, passphrase=None):
    if not path:
        return None
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return None
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_cls.from_private_key_file(path, password=(passphrase or None))
        except Exception:
            continue
    return None

def _client(host, user, key_path, passphrase=None, password=None):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, username=user, timeout=15)

    pkey = _load_pkey(key_path, passphrase)
    if pkey:
        kwargs["pkey"] = pkey
    elif not password:
        agent = paramiko.Agent()
        keys = agent.get_keys()
        if keys:
            kwargs["pkey"] = keys[0]
    if password and "pkey" not in kwargs:
        kwargs["password"] = password

    cli.connect(**kwargs)
    return cli

def run(host, user, key_path, cmd, timeout=30, passphrase=None, password=None):
    from ..settings import SETTINGS
    cli = _client(host, user, key_path, passphrase or SETTINGS.suri_passphrase, password or SETTINGS.suri_password)
    try:
        stdin, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        cli.close()

# ★ 추가: 원격 파일 쓰기(SFTP)
def sftp_write(host, user, key_path, remote_path, data: bytes, passphrase=None, password=None):
    from ..settings import SETTINGS
    cli = _client(host, user, key_path, passphrase or SETTINGS.suri_passphrase, password or SETTINGS.suri_password)
    try:
        sftp = cli.open_sftp()
        # 디렉토리 없으면 만들어주기
        dirname = os.path.dirname(remote_path)
        try:
            sftp.chdir(dirname)
        except IOError:
            # 단계별 mkdir -p
            parts = dirname.strip("/").split("/")
            cur = ""
            for p in parts:
                cur += "/" + p
                try:
                    sftp.mkdir(cur)
                except IOError:
                    pass
        with sftp.file(remote_path, "w") as f:
            f.write(data.decode() if isinstance(data, bytes) else data)
        sftp.chmod(remote_path, 0o640)
        return 0, "", ""
    finally:
        try:
            sftp.close()
        except Exception:
            pass
        cli.close()

