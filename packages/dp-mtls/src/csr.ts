import type { PublicJwk } from "@2key/dp-spec";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import {
  ED25519,
  generateEd25519KeyPair,
  importEd25519PrivateKeyFromJwk,
  importEd25519PublicKeyFromJwk,
  randomSerialHex,
} from "./ed25519.js";
import { skiSanUri } from "./materialize.js";

const DAY_MS = 24 * 60 * 60 * 1000;

function subjectAltNames(
  ski: string,
  host?: string,
): { type: "url" | "dns"; value: string }[] {
  const names: { type: "url" | "dns"; value: string }[] = [
    { type: "url", value: skiSanUri(ski) },
  ];
  if (typeof host === "string" && host.length > 0) {
    names.push({ type: "dns", value: host });
  }
  return names;
}

export type GenerateKeyAndCsrParams = {
  /** Subject common name, typically the device SKI or a human-readable label. */
  readonly commonName: string;
  /** Optional DNS SAN (e.g. `db1--acme.example`) alongside the mandatory SKI URI SAN. */
  readonly host?: string;
};

export type GenerateKeyAndCsrResult = {
  readonly privateJwk: Record<string, unknown>;
  readonly publicJwk: PublicJwk;
  readonly ski: string;
  readonly csrPem: string;
};

/**
 * Generate a device-local Ed25519 keypair and a PKCS#10 CSR for it.
 * The private key never leaves this function's return value; callers should
 * keep `privateJwk` on-device and only ship `csrPem` to a CA.
 */
export async function generateKeyAndCsr(
  params: GenerateKeyAndCsrParams,
): Promise<GenerateKeyAndCsrResult> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const { privateKey, publicKey, privateJwk, publicJwk, ski } =
    await generateEd25519KeyPair();

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${params.commonName}`,
    keys: { privateKey, publicKey },
    signingAlgorithm: ED25519,
    extensions: [
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      new x509.SubjectAlternativeNameExtension(
        subjectAltNames(ski, params.host),
        false,
      ),
    ],
  });

  return {
    privateJwk,
    publicJwk,
    ski,
    csrPem: csr.toString("pem"),
  };
}

export type CreateSelfSignedCaParams = {
  readonly commonName: string;
};

export type CreateSelfSignedCaResult = {
  readonly privateJwk: Record<string, unknown>;
  readonly publicJwk: PublicJwk;
  readonly ski: string;
  readonly caCertPem: string;
};

/** Create a self-signed Ed25519 CA (dev/test issuer for `signClientCertFromCsr`). */
export async function createSelfSignedCa(
  params: CreateSelfSignedCaParams,
): Promise<CreateSelfSignedCaResult> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const { privateKey, publicKey, privateJwk, publicJwk, ski } =
    await generateEd25519KeyPair();

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 3650 * DAY_MS);

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: `CN=${params.commonName}`,
    notBefore,
    notAfter,
    keys: { privateKey, publicKey },
    signingAlgorithm: ED25519,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
    ],
  });

  return {
    privateJwk,
    publicJwk,
    ski,
    caCertPem: cert.toString("pem"),
  };
}

export type SignClientCertFromCsrParams = {
  readonly csrPem: string;
  readonly caCertPem: string;
  /** CA's Ed25519 private JWK. Never returned; used only to sign in-process. */
  readonly caPrivateJwk: Record<string, unknown>;
  /** Subject key id to embed in the issued leaf's SAN (trusted by the CA, not the CSR). */
  readonly ski: string;
  readonly host?: string;
  /** Leaf certificate validity, in days. Default 365. */
  readonly notAfterDays?: number;
};

export type SignClientCertFromCsrResult = {
  /** PEM of the issued leaf certificate only. */
  readonly leafPem: string;
  /** PEM chain: leaf certificate followed by the CA certificate. */
  readonly chainPem: string;
};

export type IssueEndorsementFromExistingCertParams = {
  readonly entityCertPem: string;
  readonly platformCaCertPem: string;
  readonly platformCaPrivateJwk: Record<string, unknown>;
  readonly kind: "ca" | "leaf";
  /** Optional Entity CA / chain PEM to verify a leaf before endorsement. */
  readonly chainPem?: string;
  readonly subjectCn?: string;
  readonly host?: string;
  readonly notAfterDays?: number;
};

export type IssueEndorsementFromExistingCertResult = {
  readonly platformCertPem: string;
  readonly platformRootPem: string;
};

/** All PEM certificate blocks from a PEM or PEM chain. */
function pemCerts(pemOrChain: string): string[] {
  const matches = pemOrChain.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  if (!matches?.length) {
    throw new Error("No CERTIFICATE PEM block found in chain");
  }
  return matches;
}

/** Issuer CA PEM: last cert in leaf+CA chains (leaf is first). */
function issuerPemFromChain(pemOrChain: string): string {
  const certs = pemCerts(pemOrChain);
  return certs[certs.length - 1]!;
}

/**
 * Platform CA X.509 endorsement: issue a Platform-signed certificate for the
 * same SPKI as an Entity-signed CA or leaf (true X.509 issuer signature).
 */
export async function issueEndorsementFromExistingCert(
  params: IssueEndorsementFromExistingCertParams,
): Promise<IssueEndorsementFromExistingCertResult> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const entityCert = new x509.X509Certificate(params.entityCertPem);
  if (params.kind === "ca") {
    const ok = await entityCert.verify();
    if (!ok) {
      throw new Error("Entity CA certificate signature verification failed");
    }
  } else if (params.chainPem?.trim()) {
    const issuer = new x509.X509Certificate(issuerPemFromChain(params.chainPem));
    const ok = await entityCert.verify({ publicKey: issuer.publicKey });
    if (!ok) {
      throw new Error(
        "Entity leaf certificate is not signed by the provided Entity CA",
      );
    }
  }

  const platformRoot = new x509.X509Certificate(params.platformCaCertPem);
  const { privateKey: caPrivateKey } = await importEd25519PrivateKeyFromJwk(
    params.platformCaPrivateJwk,
  );

  const notBefore = new Date();
  const notAfter = new Date(
    notBefore.getTime() +
      (params.notAfterDays ?? (params.kind === "ca" ? 3650 : 365)) * DAY_MS,
  );
  const subjectCn =
    params.subjectCn ||
    entityCert.subjectName.toString().replace(/^CN=/i, "") ||
    "endorsed";

  const extensions =
    params.kind === "ca"
      ? [
          new x509.BasicConstraintsExtension(true, undefined, true),
          new x509.KeyUsagesExtension(
            x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
            true,
          ),
          await x509.SubjectKeyIdentifierExtension.create(entityCert.publicKey),
          await x509.AuthorityKeyIdentifierExtension.create(platformRoot.publicKey),
        ]
      : [
          new x509.KeyUsagesExtension(
            x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement,
            true,
          ),
          new x509.ExtendedKeyUsageExtension(
            [x509.ExtendedKeyUsage.clientAuth],
            false,
          ),
          new x509.SubjectAlternativeNameExtension(
            subjectAltNames(subjectCn, params.host),
            false,
          ),
          await x509.AuthorityKeyIdentifierExtension.create(platformRoot.publicKey),
        ];

  const endorsed = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: `CN=${subjectCn}`,
    issuer: platformRoot.subjectName,
    notBefore,
    notAfter,
    publicKey: entityCert.publicKey,
    signingKey: caPrivateKey,
    signingAlgorithm: ED25519,
    extensions,
  });

  const platformCertPem = endorsed.toString("pem");
  const platformRootPem = params.platformCaCertPem.endsWith("\n")
    ? params.platformCaCertPem
    : `${params.platformCaCertPem}\n`;

  return { platformCertPem, platformRootPem };
}

/**
 * Rebuild a self-signed CA PEM from an Ed25519 private JWK + common name.
 */
export async function caCertPemFromPrivateJwk(
  privateJwk: Record<string, unknown>,
  commonName: string,
): Promise<string> {
  x509.cryptoProvider.set(webcrypto as Crypto);
  const { privateKey } = await importEd25519PrivateKeyFromJwk(privateJwk);
  const { d: _d, ...publicJwkRest } = privateJwk;
  const publicKey = await importEd25519PublicKeyFromJwk(
    publicJwkRest as PublicJwk,
  );
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 3650 * DAY_MS);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: `CN=${commonName}`,
    notBefore,
    notAfter,
    keys: { privateKey, publicKey },
    signingAlgorithm: ED25519,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
    ],
  });
  return cert.toString("pem");
}

/**
 * Sign a PKCS#10 CSR with a CA private key, producing a DP client leaf cert.
 * The SAN (SKI URI + optional host) is set from trusted `params`, not copied
 * from the CSR, so a compromised/incorrect CSR cannot forge its own identity.
 */
export async function signClientCertFromCsr(
  params: SignClientCertFromCsrParams,
): Promise<SignClientCertFromCsrResult> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const csr = new x509.Pkcs10CertificateRequest(params.csrPem);
  const csrIsValid = await csr.verify();
  if (!csrIsValid) {
    throw new Error("CSR signature verification failed");
  }

  const caCert = new x509.X509Certificate(params.caCertPem);
  const { privateKey: caPrivateKey } = await importEd25519PrivateKeyFromJwk(
    params.caPrivateJwk,
  );

  const notBefore = new Date();
  const notAfter = new Date(
    notBefore.getTime() + (params.notAfterDays ?? 365) * DAY_MS,
  );

  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: `CN=${params.ski}`,
    issuer: caCert.subjectName,
    notBefore,
    notAfter,
    publicKey: csr.publicKey,
    signingKey: caPrivateKey,
    signingAlgorithm: ED25519,
    extensions: [
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      new x509.SubjectAlternativeNameExtension(
        subjectAltNames(params.ski, params.host),
        false,
      ),
      await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey),
    ],
  });

  const leafPem = leaf.toString("pem");
  const caCertPemNormalized = params.caCertPem.endsWith("\n")
    ? params.caCertPem
    : `${params.caCertPem}\n`;

  return {
    leafPem,
    chainPem: `${leafPem}${caCertPemNormalized}`,
  };
}
