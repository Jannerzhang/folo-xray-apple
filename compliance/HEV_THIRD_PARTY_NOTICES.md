# Hev evaluation notices

This notice applies only to the source-built Hev evaluation closure. It is not
an approval to ship a Hev artifact in the App Store client. The final release
must retain each upstream license file and publish the exact source revisions.

| Component | Revision | License | License text SHA-256 | Source |
| --- | --- | --- | --- | --- |
| hev-socks5-tunnel | `a404c11cd61d8e29e6f4c590b7e659d127fb843e` | MIT | `3cca1a91ca82e9b9c41852945ef15858f932828ceeb765b86bc1fe3f39127514` | https://github.com/heiher/hev-socks5-tunnel/tree/a404c11cd61d8e29e6f4c590b7e659d127fb843e |
| hev-socks5-core | `162dd996299fc2d2bff2dd63728f8a2cd71ed31a` | MIT | `3cca1a91ca82e9b9c41852945ef15858f932828ceeb765b86bc1fe3f39127514` | https://github.com/heiher/hev-socks5-core/tree/162dd996299fc2d2bff2dd63728f8a2cd71ed31a |
| hev-task-system | `328f35d903221b51811b3d02b277d665dfbdc75f` | MIT | `3cca1a91ca82e9b9c41852945ef15858f932828ceeb765b86bc1fe3f39127514` | https://github.com/heiher/hev-task-system/tree/328f35d903221b51811b3d02b277d665dfbdc75f |
| lwip | `2a11c14c7a32887af25a034e82ef18b0b12076ac` | BSD-3-Clause | `ef4aac92e05e87cd1cdc140870ed52206ba03d4a7fe46c1e11d7ffa6c87d252b` | https://github.com/heiher/lwip/tree/2a11c14c7a32887af25a034e82ef18b0b12076ac |
| yaml | `efa36117a8646d26d12b58e05bac472d7854a70d` | MIT | `3cca1a91ca82e9b9c41852945ef15858f932828ceeb765b86bc1fe3f39127514` | https://github.com/heiher/yaml/tree/efa36117a8646d26d12b58e05bac472d7854a70d |

The candidate repository also contains Windows-only Wintun material and an
Apple host utun backend. Both are explicitly excluded from the iOS evaluation
closure and must not enter a Packet Tunnel artifact.
