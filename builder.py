"""
CFFI definitions of PF related things.

(c) 2022 Jasper Spaans <github:jap> as far as this can be copyrighted
"""

from cffi import FFI


def build_it():
    ffibuilder = FFI()
    ffibuilder.set_source(
        '_pftables',
        r"""
        #include <net/if.h>
        #include <net/pfvar.h>
        #include <sys/ioccom.h>
        """,
        libraries=[],
    )

    with open('prebuilder.out') as f:
        constants = f.read()

    ffibuilder.cdef(
        constants
        + r"""
        // netinet/in.h
        struct in_addr {
            uint32_t s_addr;
        };

        // netinet6/in6.h
        struct in6_addr {
                union {
                        uint8_t         __u6_addr8[16];
                        uint16_t        __u6_addr16[8];
                        uint32_t        __u6_addr32[4];
                } __u6_addr;                    /* 128-bit IP6 address */
        };

        // net/pfvar.h

        struct pfr_table {
            char                     pfrt_anchor[MAXPATHLEN];
            char                     pfrt_name[PF_TABLE_NAME_SIZE];
            uint32_t                pfrt_flags;
            uint8_t                 pfrt_fback;
        };

        struct pfr_addr {
            union {
                struct in_addr   _pfra_ip4addr;
                struct in6_addr  _pfra_ip6addr;
            }                pfra_u;
            uint8_t         pfra_af;
            uint8_t         pfra_net;
            uint8_t         pfra_not;
            uint8_t         pfra_fback;
        };

        struct pfioc_table {
            struct pfr_table         pfrio_table;
            void                    *pfrio_buffer;
            int                      pfrio_esize;
            int                      pfrio_size;
            int                      pfrio_size2;
            int                      pfrio_nadd;
            int                      pfrio_ndel;
            int                      pfrio_nchange;
            int                      pfrio_flags;
            uint32_t                 pfrio_ticket;
        };
        """
    )

    ffibuilder.compile()


if __name__ == '__main__':
    build_it()
