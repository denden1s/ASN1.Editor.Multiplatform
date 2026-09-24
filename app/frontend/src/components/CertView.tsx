import type { ReactNode } from 'react';
import type { AsnCert } from '../asn1';

interface CertViewProps {
  cert: AsnCert | null;
  certError: string | null;
}

function isNotCertificate(msg: string | null): boolean {
  return !!msg && /not an x\.509 certificate/i.test(msg);
}

export function CertView({ cert, certError }: CertViewProps) {
  if (!cert) {
    return (
      <div className="cert-empty">
        {certError && !isNotCertificate(certError) ? certError : 'Not a certificate'}
      </div>
    );
  }

  const bc = cert.basicConstraints ?? null;
  const bcText = !bc
    ? null
    : bc.ca
      ? `CA: TRUE${bc.pathLen !== undefined ? `, path length: ${bc.pathLen}` : ''}`
      : 'CA: FALSE';

  return (
    <div className="cert" aria-label="Certificate view">
      <section className="cert-sec">
        <div className="cert-sec-h">General</div>
        <Row k="Subject">{cert.subject || <span className="cdim">—</span>}</Row>
        <Row k="Issuer">{cert.issuer || <span className="cdim">—</span>}</Row>
        <Row k="Serial">
          <span className="cmono">{cert.serialHex}</span>
          {cert.serialDec && <span> ({cert.serialDec})</span>}
        </Row>
        <Row k="Valid from">{cert.notBefore}</Row>
        <Row k="Valid until">{cert.notAfter}</Row>
        <Row k="Signature">
          {cert.signatureAlgorithm}
          {cert.signatureAlgorithmOid && (
            <span className="coid"> ({cert.signatureAlgorithmOid})</span>
          )}
        </Row>
        <Row k="SHA-1">
          <span className="cmono">{cert.fingerprints?.sha1 ?? ''}</span>
        </Row>
        <Row k="SHA-256">
          <span className="cmono">{cert.fingerprints?.sha256 ?? ''}</span>
        </Row>
      </section>

      <section className="cert-sec">
        <div className="cert-sec-h">Details</div>
        <Row k="Version">v{cert.version}</Row>
        <Row k="Issuer">
          <AttrList attrs={cert.issuerAttributes} />
        </Row>
        <Row k="Subject attrs">
          <AttrList attrs={cert.subjectAttributes} />
        </Row>
        <Row k="SANs">
          {(cert.subjectAlternativeNames ?? []).length > 0 ? (
            (cert.subjectAlternativeNames ?? []).map((s) => (
              <div key={s} className="cline">
                {s}
              </div>
            ))
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        <Row k="Key usage">
          {(cert.keyUsage ?? []).length > 0 ? (
            (cert.keyUsage ?? []).join(', ')
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        <Row k="Ext key usage">
          {(cert.extendedKeyUsage ?? []).length > 0 ? (
            (cert.extendedKeyUsage ?? []).join(', ')
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        {bcText && <Row k="Constraints">{bcText}</Row>}
        {cert.subjectKeyId && (
          <Row k="Subject key ID">
            <span className="cmono cwrap">{cert.subjectKeyId}</span>
          </Row>
        )}
        {cert.authorityKeyId && (
          <Row k="Authority key ID">
            <span className="cmono cwrap">{cert.authorityKeyId}</span>
          </Row>
        )}
        <Row k="Public key">
          {cert.publicKeyAlgorithm}
          {cert.publicKeyAlgorithmOid && (
            <span className="coid"> ({cert.publicKeyAlgorithmOid})</span>
          )}
          {cert.publicKeyHex && <div className="cmono cwrap">{cert.publicKeyHex}</div>}
        </Row>
        {(cert.extensions ?? []).length > 0 && (
          <Row k="Extensions">
            {(cert.extensions ?? []).map((e) => (
              <div key={e.oid} className="cext">
                <span className="cmono">{e.oid}</span>
                {e.critical && <span className="ccrit">critical</span>}
                {e.hex && <div className="cmono cwrap">{e.hex}</div>}
              </div>
            ))}
          </Row>
        )}
      </section>
    </div>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="crow">
      <span className="ckey">{k}</span>
      <span className="cval">{children}</span>
    </div>
  );
}

function AttrList({ attrs }: { attrs: AsnCert['issuerAttributes'] }) {
  const list = attrs ?? [];
  if (list.length === 0) {
    return <span className="cdim">—</span>;
  }
  return (
    <>
      {list.map((a) => (
        <div key={`${a.oid}=${a.value}`} className="cline">
          {a.name || a.oid}
          {a.name && <span className="coid"> ({a.oid})</span>}
          {' = '}
          {a.value}
        </div>
      ))}
    </>
  );
}
