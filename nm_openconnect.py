#!/usr/bin/env python3
"""This script provide much better flexibility in comparison to original
nm-openconnect plugin. It can automatically feed password on stdin and pass
form data in command line options as well.
"""
import logging
import os
import threading
from argparse import ArgumentParser, Namespace
from enum import IntEnum
from functools import wraps
from json import dumps
from logging.handlers import SysLogHandler
from os import getenv
from pwd import getpwnam
from subprocess import Popen, PIPE, TimeoutExpired
from time import sleep
from typing import Any, Optional

import dbus
import dbus.mainloop.glib
import dbus.service
import netifaces as ni
from dbus.service import method, signal
from gi.repository import GLib
from netaddr.ip import IPAddress

NM_DBUS_SERVICE_CISCO = 'org.freedesktop.NetworkManager.cisco'
NM_DBUS_INTERFACE = 'org.freedesktop.NetworkManager.VPN.Plugin'
NM_DBUS_PATH = '/org/freedesktop/NetworkManager/VPN/Plugin'

NM_VPN_LOG_LEVEL = getenv('NM_VPN_LOG_LEVEL', '0')
NM_VPN_LOG_SYSLOG = getenv('NM_VPN_LOG_SYSLOG', '1')

parser = ArgumentParser()
parser.add_argument('--bus-name', default=NM_DBUS_SERVICE_CISCO,
                    help='D-Bus name to use for this instance')
parser.add_argument('--persist', default=False, action='store_true',
                    help='don’t quit when VPN connection terminates')
parser.add_argument('--debug', default=False, action='store_true',
                    help='enable verbose debug logging (may expose passwords)')


def trace(fn):
    @wraps(fn)
    def traced(self, *args, **kwargs):
        logger.debug('nm-oc: %s(%s, %s)', fn.__name__, args, kwargs)
        return fn(self, *args, **kwargs)

    return traced


def convert(obj):
    if isinstance(obj, dbus.Dictionary):
        return {str(k): convert(v) for k, v in obj.items()}
    elif isinstance(obj, dbus.Array):
        return [convert(el) for el in obj]
    elif isinstance(obj, dbus.String):
        return str(obj)
    elif isinstance(obj, dbus.UInt16 | dbus.UInt32 | dbus.UInt64):
        return int(obj)
    elif isinstance(obj, dbus.Int16 | dbus.Int32 | dbus.Int64):
        return int(obj)
    elif isinstance(obj, dbus.Boolean):
        return bool(obj)
    else:
        return obj


class ServiceState(IntEnum):
    Unknown = 0

    Init = 1

    Shutdown = 2

    Starting = 3

    Started = 4

    Stoping = 5

    Stopped = 6


class InteractiveNotSupportedError(dbus.DBusException):
    _dbus_error_name = \
        'org.freedesktop.NetworkManager.VPN.Error.InteractiveNotSupported'


class Plugin(dbus.service.Object):

    def __init__(self, loop, conn=None, object_path=None, bus_name=None):
        super().__init__(conn=conn, object_path=object_path, bus_name=bus_name)
        self.bus_name = bus_name.get_name()
        self.config = {}
        self.ip4config = {}
        self.proc: Optional[Popen] = None
        self.loop = loop

        self.gateway: Optional[str] = None
        self.command: Optional[str] = None
        self.otp_command: Optional[str] = None
        self.secret_command: Optional[str] = None
        self.username: Optional[str] = None
        self.totp: Optional[str] = None
        self.secret: Optional[str] = None
        self.password: Optional[str] = None
        self.otp: Optional[str] = None

    def run(self):
        self.loop.run()

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}',
            out_signature='')
    def Connect(self, connection: dict[str, dict[str, Any]]):
        # TODO(@daskol): What config we should use?
        connection = convert(connection)
        logger.debug('nm-oc: Connect(%s)', connection)

        env = {'NM_DBUS_SERVICE_OPENCONNECT': self.bus_name}  # Helper script.
        cmd = [self.command, '-s', 'connect', self.gateway]
        logger.debug('command to connect: %s', dumps(cmd, ensure_ascii=False))
        self.StateChanged(ServiceState.Starting)

        pwn = getpwnam(self.username)
        self.proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env,
                          preexec_fn=_demote(pwn.pw_uid, pwn.pw_gid, pwn.pw_dir))

        def _connection_callback():
            try:
                input = f'{self.username}\n{self.password}\n{self.otp}\n'.encode('utf-8')
                outs, errs = self.proc.communicate(input, timeout=60.0)
                self.proc.wait(timeout=60.0)
                logger.debug('connected to %s: stdout: %s; stderr: %s',
                             self.gateway, outs, errs)
            except TimeoutExpired:
                logger.warning('communication timed out')
            except Exception as e:
                self.proc.kill()
                outs, errs = self.proc.communicate()
                logger.error('err: %s\nstdout: %s\nstderr: %s', e, outs, errs)

            sleep(1)
            inet_ = ni.ifaddresses('cscotun0')[ni.AF_INET][0]

            logger.debug('inet: %s', inet_)

            self.SetConfig(dbus.Dictionary({
                "tundev": dbus.String("cscotun0"),
                # 'has-ip4': dbus.Boolean(True),
                # 'has-ip6': dbus.Boolean(False),
                # 'method': dbus.String("auto"),
                'gateway': dbus.UInt32(IPAddress("185.40.248.34").ipv4()),
                # 'internal-gateway': dbus.UInt32(IPAddress(inet_['peer']).ipv4()),
                'internal-gateway': dbus.UInt32(IPAddress("192.168.0.1").ipv4()),
            }, signature="sv"))

            self.SetIp4Config(dbus.Dictionary({'address': dbus.UInt32(IPAddress(inet_['addr']).ipv4()),
                                               'prefix': dbus.UInt32(IPAddress(inet_['netmask']).netmask_bits())}))

        thread = threading.Thread(target=_connection_callback)
        thread.start()

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}a{sv}')
    @trace
    def ConnectInteractive(self, connection: dict[str, dict[str, Any]],
                           details: list[Any]):
        raise InteractiveNotSupportedError

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}',
            out_signature='s')
    @trace
    def NeedSecrets(self, settings: dict[str, dict[str, Any]]) -> str:

        settings = convert(settings)

        vpn = settings.get('vpn', {})
        logger.debug("VPN: %s", vpn)

        data = vpn.get('data', {})
        logger.debug("DATA: %s", data)

        self.username = data.get('username')
        self.totp = data.get('totp')
        self.secret = data.get('secret')
        self.gateway = data.get('gateway')
        self.command = data.get('command')
        self.otp_command = data.get('otp_command')
        self.secret_command = data.get('secret_command')

        # Set or update password.
        pwn = getpwnam(self.username)

        env = {'NM_DBUS_SERVICE_OPENCONNECT': self.bus_name}  # Helper script.
        cmd = ['su', '-', self.username, self.otp_command, 'otp', self.totp]
        self.proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env)
        outs, errs = self.proc.communicate(timeout=5.0)
        self.otp = outs.decode('utf-8').strip()
        self.proc.wait(timeout=5.0)

        cmd = ['su', '-', self.username, '-c', f"{self.secret_command} lookup password {self.secret}"]
        logger.debug("secret cmd: %s", cmd)
        self.proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env)
        outs, errs = self.proc.communicate(timeout=5.0)
        self.password = outs.decode('utf-8').strip()
        self.proc.wait(timeout=5.0)
        logger.debug('secret:\n%s\n%s', outs, errs)

        section = ''  # Secret section?
        if not (self.password and self.otp):
            section = 'vpn'

        return section

    @method(dbus_interface=NM_DBUS_INTERFACE)
    @trace
    def Disconnect(self):

        # os.system('su - pvranik /home/pvranik/bin/ciscovpn-2fa.sh -- stop')
        if self.proc is None:
            logger.debug('openconnect binary has not been run: skipping it')
        else:
            self.proc.kill()
            self.proc.wait()
            logger.debug('exit code of openconnect binary is %d',
                         self.proc.returncode)

        env = {'NM_DBUS_SERVICE_OPENCONNECT': self.bus_name}  # Helper script.
        cmd = [self.command, 'disconnect']
        pwn = getpwnam(self.username)
        self.proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env,
                          preexec_fn=_demote(pwn.pw_uid, pwn.pw_gid, pwn.pw_dir))
        outs, errs = self.proc.communicate(timeout=30.0)
        self.proc.wait(timeout=60.0)
        logger.debug('connected to %s: stdout: %s; stderr: %s',
                     self.gateway, outs, errs)
        logger.debug('send stop signal to event loop')
        self.loop.quit()

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    @trace
    def SetConfig(self, config: dict[str, Any]):
        self.config = {}
        for key in ('banner', 'tundev', 'gateway', 'mtu'):
            if (val := config.get(key)) is not None:
                self.config[key] = val
        self.Config(config)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    @trace
    def SetIp4Config(self, config: dict[str, Any]):
        self.ip4config = {str(k): v for k, v in config.items()}
        self.Ip4Config({**self.config, **self.ip4config})
        self.StateChanged(ServiceState.Started)

        inet_ = ni.ifaddresses('cscotun0')[ni.AF_INET][0]
        logger.debug('inet: %s', inet_)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    @trace
    def SetIp6Config(self, config: dict[str, Any]):
        pass

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='s')
    @trace
    def SetFailure(self, reason: str):
        pass

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sa{sv}}')
    @trace
    def NewSecrets(self, connection: dict[str, dict[str, Any]]):
        pass

    @signal(dbus_interface=NM_DBUS_INTERFACE, signature='u')
    @trace
    def StateChanged(self, state: int):
        pass

    @signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    @trace
    def Config(self, config: dict[str, Any]):
        config = convert(config)
        logger.info('config: %s', dumps(config, ensure_ascii=False))

    @signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    @trace
    def Ip4Config(self, ip4config: dict[str, Any]):
        ip4config = convert(ip4config)
        logger.info('ip4config: %s', dumps(ip4config, ensure_ascii=False))

    @signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    @trace
    def Ip6Config(self, ip6config: dict[str, Any]):
        ip6config = convert(ip6config)
        logger.info('ip6config: %s', dumps(ip6config, ensure_ascii=False))


def _demote(user_uid, user_gid, user_home):
    """Pass the function 'set_ids' to preexec_fn, rather than just calling
    setuid and setgid. This will change the ids for that subprocess only"""

    def set_ids():
        os.setgid(user_gid)
        os.setuid(user_uid)
        os.environ['HOME'] = user_home

    return set_ids


class CiscoPlugin(dbus.service.Object):
    pass


def run(ns: Namespace):
    bus_loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus(mainloop=bus_loop)
    bus_name = dbus.service.BusName(ns.bus_name, bus)

    # plugin = OpenConnectPlugin(object_path=NM_DBUS_PATH,
    #                            bus_name=bus_name)
    loop = GLib.MainLoop()
    plugin = Plugin(loop=loop, object_path=NM_DBUS_PATH, bus_name=bus_name)
    plugin.run()


def main():
    ns: Namespace = parser.parse_args()

    # Configure logger on start up.
    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = SysLogHandler(facility=SysLogHandler.LOG_DAEMON, address='/dev/log')
    logger.addHandler(handler)
    logger.debug("ENV: %s", dumps("\n".join((f'{k}={v}' for k, v in os.environ.items()))))
    logger.debug('nm-oc: argv: %s', ns)
    logger.debug('nm-oc: user: %s:%s', os.geteuid(), os.getegid())

    try:
        run(ns)
    except Exception:
        logger.exception('nc-oc: throw exception')


if __name__ == '__main__':
    main()
