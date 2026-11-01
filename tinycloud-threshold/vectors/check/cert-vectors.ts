import { bytes, hex, ProtocolError, tagged } from './protocol.ts';
import { parseCertificateVectors, type CertificateCase, type CertificateFile } from './cert-schema.ts';
import { CERT_TAGS, signingKeys, decodeCertificate, verifyCertificate, authorizeCeremony, verifyClosedRound, verifyActivation, verifyFaultProof, type Anchor, type SigningKeys, type VerifiedCertificate, type VerifiedCeremony } from './certificates.ts';

interface CertificateSource { body: string; signature: string; anchor?: Anchor; pinned?: string | null }
type CeremonyCase = Extract<CertificateCase, { operation: 'authorize_ceremony' }>;
export interface CertificateReport { passed: string[]; signingKeys: number }

export class CertificateRegistry {
  readonly keys: SigningKeys;
  private readonly certificates = new Map<string, CertificateSource[]>();
  private readonly ceremonies = new Map<string, CeremonyCase[]>();
  private readonly verifiedCertificates = new Map<string, VerifiedCertificate>();
  private readonly verifiedCeremonies = new Map<string, VerifiedCeremony>();
  private readonly visiting = new Set<string>();
  constructor(file: CertificateFile) {
    this.keys = signingKeys(file.seeds.ed25519);
    for (const c of file.cases) {
      let source: CertificateSource | undefined;
      if (c.operation === 'verify_certificate') {
        source = { body: c.inputs.body, signature: c.inputs.owner_signature, anchor: { owner: c.inputs.expected_owner, network: c.inputs.network }, pinned: c.inputs.pinned_predecessor };
      } else if (c.operation === 'verify_fault_proof' && 'certificate_body' in c.inputs) {
        source = { body: c.inputs.certificate_body, signature: c.inputs.owner_signature };
      }
      if (source) {
        const digest = hex(tagged(CERT_TAGS.certificate, bytes(source.body)));
        this.certificates.set(digest, [...(this.certificates.get(digest) ?? []), source]);
      }
      if (c.operation === 'authorize_ceremony') {
        const digest = hex(tagged(CERT_TAGS.ceremony, bytes(c.inputs.body)));
        this.ceremonies.set(digest, [...(this.ceremonies.get(digest) ?? []), c]);
      }
    }
  }
  certificate(digest: string): VerifiedCertificate {
    const sources = this.certificates.get(digest);
    if (!sources?.length) throw new ProtocolError('UnresolvedReference');
    if (sources.length !== 1) throw new ProtocolError('AmbiguousReference');
    const cached = this.verifiedCertificates.get(digest);
    if (cached) return cached;
    if (this.visiting.has(digest)) throw new ProtocolError('UnresolvedReference');
    this.visiting.add(digest);
    try {
      const source = sources[0]!, body = decodeCertificate(bytes(source.body));
      const prior = source.pinned === undefined ? (body.previous ? hex(body.previous) : null) : source.pinned;
      const previous = prior === null ? undefined : this.certificate(prior);
      const anchor = source.anchor ?? previous?.anchor;
      if (!anchor) throw new ProtocolError('UnresolvedAnchor');
      const verified = verifyCertificate(bytes(source.body), bytes(source.signature), anchor, this.keys, previous);
      this.verifiedCertificates.set(digest, verified);
      return verified;
    } finally { this.visiting.delete(digest); }
  }
  ceremony(digest: string): VerifiedCeremony {
    const sources = this.ceremonies.get(digest);
    if (!sources?.length) throw new ProtocolError('UnresolvedReference');
    if (sources.length !== 1) throw new ProtocolError('AmbiguousReference');
    const cached = this.verifiedCeremonies.get(digest);
    if (cached) return cached;
    const input = sources[0]!.inputs;
    const previous = input.pinned_predecessor === null ? undefined : this.certificate(input.pinned_predecessor);
    const anchor = 'expected_owner' in input ? { owner: input.expected_owner, network: input.network } : previous?.anchor;
    if (!anchor) throw new ProtocolError('UnresolvedAnchor');
    const verified = authorizeCeremony(bytes(input.body), bytes(input.signature), anchor, this.keys, previous);
    this.verifiedCeremonies.set(digest, verified);
    return verified;
  }
}
function compareOutputs(actual: Record<string, unknown>, expected: object) {
  for (const [field, value] of Object.entries(expected)) {
    if (JSON.stringify(actual[field]) !== JSON.stringify(value)) throw new Error(`${field}: observed ${JSON.stringify(actual[field])}; expected ${JSON.stringify(value)}`);
  }
}
function execute(c: CertificateCase, registry: CertificateRegistry): Record<string, unknown> {
  switch (c.operation) {
    case 'verify_certificate': {
      const cert = registry.certificate(hex(tagged(CERT_TAGS.certificate, bytes(c.inputs.body)))), b = cert.body;
      return { commitments: b.commitments.map(hex), digest: hex(cert.digest), epoch: Number(b.epoch), genesis_t: b.genesisThreshold, members: b.members.length, mpk: hex(b.mpk), owner_statement: hex(cert.ownerPreimage), public_shares: b.members.map(m => ({ index: m.index, point: hex(cert.keyset.publicShares.get(m.index)!.toBytes()) })), rekey: Number(b.rekey), threshold: b.threshold };
    }
    case 'authorize_ceremony': {
      const ceremony = registry.ceremony(hex(tagged(CERT_TAGS.ceremony, bytes(c.inputs.body))));
      return { digest: hex(ceremony.digest), signing_preimage: hex(ceremony.digest) };
    }
    case 'verify_closed_round': {
      const i = c.inputs;
      const round = verifyClosedRound(registry.ceremony(i.ceremony_digest), bytes(i.closure), bytes(i.owner_signature), i.round, bytes(i.previous), i.messages.map(m => ({ body: bytes(m.body), signature: bytes(m.signature) })), registry.keys);
      return { owner_preimage: hex(round.ownerPreimage), transcript_hash: hex(round.transcript) };
    }
    case 'verify_activation': {
      const i = c.inputs, cert = registry.certificate(i.candidate);
      const result = verifyActivation(cert, i.receipts.map(r => ({ index: r.index, signature: bytes(r.signature) })), 'budget' in i ? i.budget : null, bytes(i.owner_signature), registry.keys);
      if ('activation_preimage' in i && i.activation_preimage !== hex(result.preimage)) throw new ProtocolError('InvalidReadiness');
      for (const [position, receipt] of i.receipts.entries()) {
        if ('encoding' in receipt) {
          const computed = result.receipts[position]!;
          compareOutputs({ encoding: hex(computed.encoding), index: computed.index, readiness_preimage: hex(computed.preimage), receipt_hash: hex(computed.hash), signature: hex(computed.signature) }, receipt);
        }
      }
      return { accepted: true, activation_preimage: hex(result.preimage) };
    }
    case 'decode_certificate': {
      decodeCertificate(bytes(c.inputs.body));
      return {};
    }
    case 'verify_fault_proof': {
      const i = c.inputs;
      let cert: VerifiedCertificate;
      try {
        cert = registry.certificate('certificate' in i ? i.certificate : hex(tagged(CERT_TAGS.certificate, bytes(i.certificate_body))));
      } catch (e) {
        if (e instanceof ProtocolError && !['UnresolvedReference', 'AmbiguousReference', 'UnresolvedAnchor'].includes(e.code)) return { verdict: 'NotAFault', reason: e.code };
        throw e;
      }
      return { ...verifyFaultProof(cert, bytes(i.request), bytes(i.share), bytes(i.signature), registry.keys) };
    }
    default: { const exhaustive: never = c; throw new Error(`unsupported operation: ${exhaustive}`); }
  }
}
export function checkCertificateVectors(input: unknown): CertificateReport {
  const file = parseCertificateVectors(input), registry = new CertificateRegistry(file), passed: string[] = [];
  for (const c of file.cases) {
    try {
      let result: Record<string, unknown> | undefined;
      let error: string | undefined;
      try { result = execute(c, registry); } catch (e) {
        if (!(e instanceof ProtocolError)) throw e;
        error = e.code;
      }
      if ('error' in c) {
        if (error !== c.error) throw new Error(`computed error: observed ${error}; expected ${c.error}`);
      } else {
        if (error !== undefined) throw new Error(`computed error: ${error}`);
        compareOutputs(result!, c.outputs);
      }
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { passed, signingKeys: registry.keys.size };
}
