// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/httpclients"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

var rootCmd = &cobra.Command{
	Use:   "fulcio-certificate-gen",
	Short: "Generate an OIDC certificate",
	Long:  `Generate an OIDC certificate`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			fmt.Println("Error initializing cmd line args: ", err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Retrieve idToken from oidc provider
		idToken, err := oauthflow.OIDConnect(
			viper.GetString("oidc-issuer"),
			viper.GetString("oidc-client-id"),
			viper.GetString("oidc-client-secret"),
			oauthflow.DefaultIDTokenGetter,
		)
		if err != nil {
			return err
		}
		fmt.Println("\nReceived OpenID Scope retrieved for account:", idToken.Subject)

		signer, err := signature.NewDefaultECDSASignerVerifier()
		if err != nil {
			return err
		}

		pub, err := signer.PublicKey(ctx)
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}

		proof, _, err := signer.Sign(ctx, []byte(idToken.Subject))
		if err != nil {
			return err
		}

		certResp, err := httpclients.GetCert(idToken, proof, pubBytes, viper.GetString("fulcio-server"))
		if err != nil {
			switch t := err.(type) {
			case *operations.SigningCertDefault:
				if t.Code() == http.StatusInternalServerError {
					return err
				}
			default:
				return err
			}
			os.Exit(1)
		}

		clientPEM, rootPEM := pem.Decode([]byte(certResp.Payload))
		certPEM := pem.EncodeToMemory(clientPEM)

		rootBlock, _ := pem.Decode([]byte(rootPEM))
		if rootBlock == nil {
			return err
		}

		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			return err
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}

		outputFileStr := viper.GetString("output")
		outputFile := os.Stdout
		if outputFileStr != "-" {
			var err error
			outputFile, err = os.Create(filepath.Clean(outputFileStr))
			if err != nil {
				return err
			}
			defer func() {
				if err := outputFile.Close(); err != nil {
					fmt.Fprint(os.Stderr, err)
				}
			}()
		}
		fmt.Fprint(outputFile, cert)
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "OIDC provider to be used to issue ID token")
	rootCmd.PersistentFlags().String("oidc-client-id", "sigstore", "client ID for application")
	rootCmd.PersistentFlags().String("oidc-client-secret", "", "client secret for application")
	rootCmd.PersistentFlags().StringP("output", "o", "-", "output file to write certificate chain to")
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
