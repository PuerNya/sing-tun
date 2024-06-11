package tun

import (
	"context"

	"github.com/sagernet/sing/common/logger"

	"go4.org/netipx"
)

type AutoRedirect interface {
	Start() error
	Close() error
	UpdateRouteAddressSet() error
}

type AutoRedirectOptions struct {
	TunOptions             *Options
	Context                context.Context
	Handler                Handler
	Logger                 logger.Logger
	TableName              string
	DisableNFTables        bool
	CustomRedirectPort     func() int
	RouteAddressSet        *[]*netipx.IPSet
	RouteExcludeAddressSet *[]*netipx.IPSet
}
