"""
Small library to interact with BSD PF tables using ioctls

(c) 2022 Jasper Spaans <github:jap>
"""
import fcntl
import ipaddress
import logging
import socket
from typing import Any, ClassVar, List, Tuple, Union

import attrs
from _pftables import ffi, lib

log = logging.getLogger(__name__)


@attrs.define(kw_only=True)
class PfTable:
    name: str  # len < PF_TABLE_NAME_SIZE [32]
    anchor: str = ''  # len < MAXPATHLEN [1024]
    flags: int = 0  # int32
    fback: int = 0  # int8

    def to_ffi(self) -> Any:
        table = ffi.new('struct pfr_table *')
        return self.into_ffi(table)

    def into_ffi(self, table: Any) -> Any:
        """Convert this PfTable to a proper struct pfr_table"""
        table.pfrt_anchor = self.anchor.encode()
        table.pfrt_name = self.name.encode()
        table.pfrt_flags = self.flags
        table.pfrt_fback = self.fback

        return table

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PfTable':
        raise NotImplementedError

    def register(self) -> bool:
        """Registers this table with the OS.

        Returns whether the table was registered.
        """
        log.info('Registering table %r', self.name)
        io = PfiocAddTable(tables=[self])
        table, _ = self._call_ioctl(io)
        return table.pfrio_nadd == 1

    def unregister(self) -> bool:
        """Unregisters this table with the OS.

        Returns whether the table was registered.
        """
        log.info('Unregistering table %r', self.name)
        io = PfiocDelTable(tables=[self])
        table, _ = self._call_ioctl(io)
        return table.pfrio_ndel == 1

    def add(self, address: str, *, not_: bool = False) -> bool:
        """Adds an IP to this table.

        Returns whether the address was added.
        """
        pfr_addr = PfrAddr(address=address, not_=not_)
        log.debug('Adding %r to table %r', pfr_addr, self.name)
        io = PfiocAddAddr(table=self, addrs=[pfr_addr])
        table, _ = self._call_ioctl(io)
        return table.pfrio_nadd == 1

    def remove(self, address: str, *, not_: bool = False) -> bool:
        """Removes an IP from this table.

        Returns whether the address was removed.
        """
        pfr_addr = PfrAddr(address=address, not_=not_)
        log.debug('Removing %r from table %r', pfr_addr, self.name)
        io = PfiocDelAddr(table=self, addrs=[pfr_addr])
        table, _ = self._call_ioctl(io)
        return table.pfrio_ndel == 1

    def get(self) -> List['PfrAddr']:
        """Returns the current list of addresses in this table."""
        # probe for size = 1 first
        query_size = 1
        while True:
            io = PfiocGetAddr(table=self, size=query_size)
            table, buffers = self._call_ioctl(io)
            result_size = table.pfrio_size

            if result_size <= query_size:
                break
            log.debug(
                'Query with space for %d failed, retrying with %d',
                query_size,
                result_size,
            )
            query_size = result_size

        addrs = [PfrAddr.from_ffi(buffer) for buffer in buffers[0:result_size]]
        return addrs

    def _call_ioctl(self, io) -> Tuple[Any, Any]:
        # need to hold on to the buffers until after the call!
        table, buffers = io.to_ffi()
        with open('/dev/pf', 'w') as fd:
            fcntl.ioctl(fd, io.ioctl, ffi.buffer(table), 1)
        return table, buffers


@attrs.define(kw_only=True)
class PfrAddr:
    address: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = attrs.field(
        converter=ipaddress.ip_network
    )
    not_: int = 0  # int8
    fback: int = attrs.field(default=0, repr=False)  # int8

    def to_ffi(self) -> Any:
        """Convert this PfrAddr to a struct pfr_addr"""
        addr = ffi.new('struct pfr_addr *')
        return self.into_ffi(addr)

    def into_ffi(self, addr: Any) -> Any:
        """Write the contents of this PfrAddr into a preallocated struct pfr_addr"""
        if isinstance(self.address, ipaddress.IPv4Network):
            addr4 = ffi.from_buffer(
                'struct in_addr *', self.address.network_address.packed
            )
            addr.pfra_u._pfra_ip4addr = addr4[0]
            af = 2  # AF_INET
        elif isinstance(self.address, ipaddress.IPv6Network):
            addr6 = ffi.from_buffer(
                'struct in6_addr *', self.address.network_address.packed
            )
            addr.pfra_u._pfra_ip6addr = addr6[0]
            af = 28  # AF_INET6
        else:
            raise TypeError('address is not the expected type')

        addr.pfra_af = af
        addr.pfra_net = self.address.prefixlen
        addr.pfra_not = self.not_
        addr.pfra_fback = self.fback
        return addr

    @classmethod
    def from_ffi(cls, buffer: Any) -> 'PfrAddr':
        # buffer is a struct pfr_addr
        address: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
        if buffer.pfra_af == 2:
            address = ipaddress.IPv4Network(
                (socket.htonl(buffer.pfra_u._pfra_ip4addr.s_addr), buffer.pfra_net)
            )
        elif buffer.pfra_af == 28:
            # this needs this getattr because otherwise there is going
            # to be a bit of name mangling that is not easy to work around
            addr_bytes = ffi.buffer(
                getattr(
                    getattr(buffer.pfra_u._pfra_ip6addr, '__u6_addr'),
                    '__u6_addr8',
                )
            )[:]

            address = ipaddress.IPv6Network((addr_bytes, buffer.pfra_net))
        else:
            raise ValueError(f'unexpected address family {buffer.pfra_af}')

        not_ = buffer.pfra_not
        fback = buffer.pfra_fback

        return cls(address=address, not_=not_, fback=fback)


@attrs.define()
class PfiocTable:
    table: PfTable
    esize: int
    size: int
    size2: int
    nadd: int
    ndel: int
    nchange: int
    flags: int
    ticket: int  # int32


@attrs.define(kw_only=True)
class PfiocAddDelTable:
    tables: List[PfTable]
    nadd: int = 0

    def to_ffi(self) -> Tuple[Any, Any]:
        mtable = ffi.new('struct pfioc_table *')
        mtable.pfrio_esize = ffi.sizeof('struct pfr_table')
        mtable.pfrio_size = len(self.tables)

        buffers = ffi.new(f'struct pfr_table[{len(self.tables)}]')
        for pfr_table, buffer in zip(self.tables, buffers):
            pfr_table.into_ffi(buffer)

        mtable.pfrio_buffer = buffers

        return mtable, buffers  # need to return buffers to prevent it from being freed

    def from_ffi(cls, data: bytes) -> 'PfiocAddDelTable':
        raise NotImplementedError


@attrs.define(kw_only=True)
class PfiocAddTable(PfiocAddDelTable):
    ioctl: ClassVar[int] = lib.DIOCRADDTABLES


@attrs.define(kw_only=True)
class PfiocDelTable(PfiocAddDelTable):
    ioctl: ClassVar[int] = lib.DIOCRDELTABLES


@attrs.define(kw_only=True)
class PfiocAddDelAddr:
    table: PfTable
    addrs: List[PfrAddr]

    def to_ffi(self) -> Tuple[Any, Any]:
        mtable = ffi.new('struct pfioc_table *')
        mtable.pfrio_esize = ffi.sizeof('struct pfr_addr')
        mtable.pfrio_size = len(self.addrs)

        self.table.into_ffi(mtable.pfrio_table)

        buffers = ffi.new(f'struct pfr_addr[{len(self.addrs)}]')
        for addr, buffer in zip(self.addrs, buffers):
            addr.into_ffi(buffer)
        mtable.pfrio_buffer = buffers

        return mtable, buffers  # need to return buffers to prevent it from being freed


@attrs.define(kw_only=True)
class PfiocAddAddr(PfiocAddDelAddr):
    ioctl: ClassVar[int] = lib.DIOCRADDADDRS


@attrs.define(kw_only=True)
class PfiocDelAddr(PfiocAddDelAddr):
    ioctl: ClassVar[int] = lib.DIOCRDELADDRS


@attrs.define(kw_only=True)
class PfiocGetAddr:
    table: PfTable
    size: int
    ioctl: ClassVar[int] = lib.DIOCRGETADDRS

    def to_ffi(self) -> Tuple[Any, Any]:
        mtable = ffi.new('struct pfioc_table *')
        mtable.pfrio_esize = ffi.sizeof('struct pfr_addr')
        mtable.pfrio_size = self.size

        self.table.into_ffi(mtable.pfrio_table)

        buffers = ffi.new(f'struct pfr_addr[{self.size}]')
        mtable.pfrio_buffer = buffers

        return mtable, buffers


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    x = PfTable(name='henk2')
    print(x.register())

    hosts = ['198.51.100.1', '192.0.2.0/24', '2001:db8::/64']

    for host in hosts:
        print(x.add(host))
    print(x.add('192.0.2.4', not_=True))

    print(x.get())

    for host in hosts:
        print(x.remove(host))
    print(x.remove('192.0.2.4', not_=True))

    print(x.unregister())
