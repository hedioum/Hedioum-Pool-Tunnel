package firewall

import "testing"

func TestParseInputRestrictive(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		want  bool
	}{
		{
			name:  "default drop",
			rules: "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n",
			want:  true,
		},
		{
			name:  "default reject",
			rules: "-P INPUT REJECT\n",
			want:  true,
		},
		{
			name:  "default accept",
			rules: "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 80 -j ACCEPT\n",
			want:  false,
		},
		{
			name:  "empty",
			rules: "",
			want:  false,
		},
		{
			name:  "drop with surrounding whitespace",
			rules: "  -P INPUT DROP  \n",
			want:  true,
		},
	}
	for _, c := range cases {
		if got := parseInputRestrictive(c.rules); got != c.want {
			t.Errorf("%s: parseInputRestrictive = %v, want %v", c.name, got, c.want)
		}
	}
}
