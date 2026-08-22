// SPDX-License-Identifier: MPL-2.0
//
// Folo does not expose a local Xray listener. The Apple Packet Tunnel owns
// the TUN/socket adapter, so the core only needs a feature-compatible empty
// inbound manager. Keeping this small manager in the Folo distro avoids
// linking Xray's TCP/UDP/Unix listener workers and their server surface.
package foloinbound

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/inbound"
)

type manager struct{}

func (*manager) Type() interface{} {
	return inbound.ManagerType()
}

func (*manager) Start() error {
	return nil
}

func (*manager) Close() error {
	return nil
}

func (*manager) GetHandler(context.Context, string) (inbound.Handler, error) {
	return nil, common.ErrNoClue
}

func (*manager) AddHandler(context.Context, inbound.Handler) error {
	return common.ErrNoClue
}

func (*manager) RemoveHandler(context.Context, string) error {
	return common.ErrNoClue
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.InboundConfig)(nil), func(context.Context, interface{}) (interface{}, error) {
		return &manager{}, nil
	}))
}
