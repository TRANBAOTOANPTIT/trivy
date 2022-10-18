package release

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_osReleaseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		input     analyzer.AnalysisInput
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "alpine",
			inputFile: filepath.Join("testdata", "alpine"),
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15.4"},
			},
		},
		{
			name:      "openSUSE-leap 15.2.1",
			inputFile: "testdata/opensuseleap-15.2.1",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.OpenSUSELeap, Name: "15.2.1"},
			},
		},
		{
			name:      "openSUSE-leap 42.3",
			inputFile: "testdata/opensuseleap-42.3",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.OpenSUSELeap, Name: "42.3"},
			},
		},
		{
			name:      "openSUSE-tumbleweed",
			inputFile: filepath.Join("testdata", "opensusetumbleweed"),
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.OpenSUSETumbleweed, Name: "20220412"},
			},
		},
		{
			name:      "SUSE Linux Enterprise Server",
			inputFile: filepath.Join("testdata", "sles"),
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.SLES, Name: "15.3"},
			},
		},
		{
			name:      "Photon OS",
			inputFile: filepath.Join("testdata", "photon"),
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Photon, Name: "4.0"},
			},
		},
		{
			name:      "Photon OS",
			inputFile: filepath.Join("testdata", "photon"),
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Photon, Name: "4.0"},
			},
		},
		{
			name:      "Unknown OS",
			inputFile: filepath.Join("testdata", "unknown"),
			want:      nil,
		},
		{
			name:      "No 'ID' field",
			inputFile: filepath.Join("testdata", "no-id"),
			want:      nil,
		},
		{
			name:      "No 'VERSION_ID' field",
			inputFile: filepath.Join("testdata", "no-version"),
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := osReleaseAnalyzer{}
			res, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: "etc/os-release",
				Content:  f,
			})

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, res)
		})
	}
}
