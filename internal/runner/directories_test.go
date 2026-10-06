package runner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

type directoryLogWriter struct {
	records []string
}

func (w *directoryLogWriter) Write(data []byte, _ levels.Level) {
	w.records = append(w.records, string(data))
}

func TestDirectoryInfoContainsKnownLabels(t *testing.T) {
	info := DirectoryInfo()
	cfg := config.DefaultConfig

	require.Equal(t, strings.Join([]string{
		fmt.Sprintf("Infinity Config Directory: %s", cfg.GetConfigDir()),
		fmt.Sprintf("Infinity State Directory: %s", cfg.GetStateDir()),
		fmt.Sprintf("Infinity Cache Directory: %s", cfg.GetCacheDir()),
		fmt.Sprintf("Infinity Session Directory: %s", pdcpauth.PDCPDir),
		"",
	}, "\n"), info)
	require.Equal(t, 4, strings.Count(info, "\n"))
}

func TestLogDirectoryInfoContainsKnownLabels(t *testing.T) {
	writer := &directoryLogWriter{}
	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(true))
	logger.SetWriter(writer)
	logger.SetMaxLevel(levels.LevelInfo)

	LogDirectoryInfo(logger)

	require.Equal(t, []string{
		fmt.Sprintf("[INF] Infinity Config Directory: %s", config.DefaultConfig.GetConfigDir()),
		fmt.Sprintf("[INF] Infinity State Directory: %s", config.DefaultConfig.GetStateDir()),
		fmt.Sprintf("[INF] Infinity Cache Directory: %s", config.DefaultConfig.GetCacheDir()),
		fmt.Sprintf("[INF] Infinity Session Directory: %s", pdcpauth.PDCPDir),
	}, writer.records)
}
