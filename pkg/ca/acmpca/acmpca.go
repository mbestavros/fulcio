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

package acmpca

import (
	"context"
	"time"

	//"crypto/rand"
	//"crypto/x509"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/sigstore/fulcio/pkg/log"
)

func GetClientCertificate(ctx context.Context, caArn string) (string, []string, error) {

	// Generate a CSR for ACM PCA
	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SignatureAlgorithm.ECDSAWithSHA384,
		Subject: ,
		DNSNames: ,
		EmailAddresses: ,
		IPAddresses: ,
		URIs: ,
		ExtraExtensions: ,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, TODO)
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Create an ACM PCA service client
	client := acmpca.NewFromConfig(cfg)

	// Get a CSR from our PCA
	// csrOutput, err := client.GetCertificateAuthorityCsr(ctx, &acmpca.GetCertificateAuthorityCsrInput{
	// 	CertificateAuthorityArn: caArn,
	// })
	// if err != nil {
	// 	log.Logger.Fatal(err)
	// }

	// Issue a certificate
	issueOutput, err := client.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: caArn,
		Csr: csrBytes,
		SigningAlgorithm: types.SigningAlgorithm.SigningAlgorithmSha384withecdsa,
		Validity: types.Validity{
			Type: types.ValidityPeriodType.ValidityPeriodTypeAbsolute,
			Value: time.Now().Add(time.Minute * 10),
		},
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Get the issued certificate
	getOutput, err := client.GetCertificate(ctx, &acmpca.GetCertificateInput{
		CertificateArn: issueOutput.CertificateArn,
		CertificateAuthorityArn: caArn,
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Return the PEM-encoded certificate and certificate chain
	// TODO: convert certificate chain to string array? string[]
	return getOutput.Certificate, getOutput.CertificateChain, nil
}
