"""
Little helper to generate 'prebuilder.c' which can then be used to
write out some #defines containing system constants.

(c) 2022 Jasper Spaans <github:jap>
"""


def generate_prebuilder_c():
    with open('prebuilder.c', 'w') as f:
        f.write(
            """
            #include <stdio.h>
            #include <stdint.h>
            #include <sys/limits.h>
            #include <sys/ioccom.h>
            #include <netinet/in.h>
            #include <net/if.h>
            #include <net/pfvar.h>

            int main() {
            """
        )
        # include <netpfil/pf/pf.h>

        for var in [
            'MAXPATHLEN',
            'PF_TABLE_NAME_SIZE',
        ]:
            f.write(
                rf"""
                printf("#define {var} %d\n", ({var}));
                """
            )
        for var in [
            'DIOCRADDTABLES',
            'DIOCRDELTABLES',
            'DIOCRADDADDRS',
            'DIOCRDELADDRS',
            'DIOCRGETADDRS',
        ]:
            f.write(
                rf"""
                printf("#define {var} %luU\n", ({var}));
                """
            )
        f.write(
            """
            }
            """
        )


if __name__ == '__main__':
    generate_prebuilder_c()
