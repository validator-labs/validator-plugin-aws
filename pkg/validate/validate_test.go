package validate

import (
	"os"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	//+kubebuilder:scaffold:imports
)

func Test_validateAuth(t *testing.T) {
	type args struct {
		auth v1alpha1.AwsAuth
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No error for valid inline auth data",
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "b",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "No panic for nil auth.Credentials",
			args: args{
				auth: v1alpha1.AwsAuth{},
			},
			wantErr: true,
		},
		{
			name: "Error for invalid access key ID",
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "",
						SecretAccessKey: "b",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error for invalid secret access key",
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateAuth(tt.args.auth); (err != nil) != tt.wantErr {
				t.Errorf("validateAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_configureAuth(t *testing.T) {
	type args struct {
		auth v1alpha1.AwsAuth
		log  logr.Logger
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantEnvVars map[string]string
	}{
		{
			name: "Sets all env vars given inline auth config",
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "b",
					},
				},
			},
			wantErr: false,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "a",
				"AWS_SECRET_ACCESS_KEY": "b",
			},
		},
		{
			name: "No env vars set when implicit auth enabled",
			args: args{
				auth: v1alpha1.AwsAuth{
					Implicit: true,
				},
			},
			wantErr:     false,
			wantEnvVars: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the current environment variables to restore them later
			originalEnv := make(map[string]string)
			for k := range tt.wantEnvVars {
				originalEnv[k] = os.Getenv(k)
			}

			// Clean up and reset environment variables after the test
			defer func() {
				for k, v := range originalEnv {
					if v == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, v)
					}
				}
			}()

			// Check err result
			if err := configureAuth(tt.args.auth, tt.args.log); (err != nil) != tt.wantErr {
				t.Errorf("configureAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check env var result
			actualEnvVars := make(map[string]string)
			for k := range tt.wantEnvVars {
				actualEnvVars[k] = os.Getenv(k)
			}
			if !reflect.DeepEqual(actualEnvVars, tt.wantEnvVars) {
				t.Errorf("Env vars = %v; want %v", actualEnvVars, tt.wantEnvVars)
			}
		})
	}
}
