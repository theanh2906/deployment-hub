// Package web embeds the DeploymentHub single-file frontend UI bundle.
package web

import "embed"

// StaticFS holds the embedded frontend HTML bundle served at "/".
//
//go:embed index.html
var StaticFS embed.FS
