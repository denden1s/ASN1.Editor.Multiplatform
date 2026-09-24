import type { ReactNode } from 'react';
import type { AsnReq } from '../asn1';

interface ReqViewProps {
  req: AsnReq | null;
  reqError: string | null;
}

export function ReqView({ req, reqError }: ReqViewProps) {
  if (!req) {
    return (
      <div className="cert-empty">
        {reqError && !/not a certificate request/i.test(reqError)
          ? reqError
          : 'Not a certificate or request'}
      </div>
    );
  }

  return (
    <div className="cert" aria-label="Certificate request view">
      <section className="cert-sec">
        <div className="cert-sec-h">General</div>
        <Row k="Subject">{req.subject || <span className="cdim">—</span>}</Row>
        <Row k="Version">
          v{req.version + 1} <span className="coid">({req.version})</span>
        </Row>
        <Row k="Public key">
          {req.publicKeyAlgorithm}
          {req.publicKeyAlgorithmOid && (
            <span className="coid"> ({req.publicKeyAlgorithmOid})</span>
          )}
          {req.publicKeyHex && <div className="cmono cwrap">{req.publicKeyHex}</div>}
        </Row>
        <Row k="Signature">
          {req.signatureAlgorithm}
          {req.signatureAlgorithmOid && (
            <span className="coid"> ({req.signatureAlgorithmOid})</span>
          )}
          <span
            className={req.signatureValid ? 'csig-ok' : 'csig-bad'}
            title={
              req.signatureValid ? 'Self-signed signature verified' : 'Signature check failed'
            }
          >
            {req.signatureValid ? 'verified' : 'warning'}
          </span>
        </Row>
        {req.signatureHex && (
          <Row k="Signature value">
            <div className="cmono cwrap">{req.signatureHex}</div>
          </Row>
        )}
      </section>

      <section className="cert-sec">
        <div className="cert-sec-h">Details</div>
        <Row k="Subject attrs">
          <AttrList attrs={req.subjectAttributes} />
        </Row>
        <Row k="SANs">
          {(req.subjectAlternativeNames ?? []).length > 0 ? (
            (req.subjectAlternativeNames ?? []).map((s) => (
              <div key={s} className="cline">
                {s}
              </div>
            ))
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        <Row k="Key usage">
          {(req.keyUsage ?? []).length > 0 ? (
            (req.keyUsage ?? []).join(', ')
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        <Row k="Ext key usage">
          {(req.extendedKeyUsage ?? []).length > 0 ? (
            (req.extendedKeyUsage ?? []).join(', ')
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
        {(req.extensions ?? []).length > 0 && (
          <Row k="Extensions">
            {(req.extensions ?? []).map((e) => (
              <div key={e.oid} className="cext">
                <span className="cmono">{e.oid}</span>
                {e.critical && <span className="ccrit">critical</span>}
                {e.hex && <div className="cmono cwrap">{e.hex}</div>}
              </div>
            ))}
          </Row>
        )}
        <Row k="Attributes">
          {(req.attributes ?? []).length > 0 ? (
            (req.attributes ?? []).map((a) => (
              <div key={a.oid} className="cext">
                <span>{a.name || a.oid}</span>
                {a.name && <span className="coid"> ({a.oid})</span>}
                {(a.values ?? []).map((v, i) => (
                  <div key={i} className="cmono cwrap">
                    {v}
                  </div>
                ))}
              </div>
            ))
          ) : (
            <span className="cdim">—</span>
          )}
        </Row>
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

function AttrList({ attrs }: { attrs: AsnReq['subjectAttributes'] }) {
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
