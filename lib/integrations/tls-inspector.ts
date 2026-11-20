import tls from 'node:tls';

export interface TlsInspectionResult {
  inspected: boolean;
  valid: boolean;
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  authorizationError: string | null;
}

export async function inspectTlsCertificate(
  hostname: string,
  port = 443,
  timeoutMs = 5000
): Promise<TlsInspectionResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: TlsInspectionResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const protocol = socket.getProtocol() || null;
          const cipherObj = socket.getCipher();
          const validToDate = cert?.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining =
            validToDate && !Number.isNaN(validToDate.getTime())
              ? Math.floor((validToDate.getTime() - Date.now()) / (24 * 60 * 60 * 1000))
              : null;

          const issuerName = cert?.issuer
            ? cert.issuer.O || cert.issuer.CN || Object.values(cert.issuer).join(', ')
            : null;
          const subjectName = cert?.subject
            ? cert.subject.CN || cert.subject.O || Object.values(cert.subject).join(', ')
            : null;

          finish({
            inspected: true,
            valid: socket.authorized,
            protocol,
            cipher: cipherObj?.name || null,
            issuer: issuerName ? String(issuerName) : null,
            subject: subjectName ? String(subjectName) : null,
            validFrom: cert?.valid_from || null,
            validTo: cert?.valid_to || null,
            daysRemaining,
            authorizationError: socket.authorizationError
              ? String(socket.authorizationError)
              : null,
          });
        } catch (err) {
          finish({
            inspected: false,
            valid: false,
            protocol: null,
            cipher: null,
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            authorizationError: (err as Error).message,
          });
        } finally {
          socket.end();
          socket.destroy();
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish({
        inspected: false,
        valid: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        authorizationError: 'TLS handshake timed out',
      });
    });

    socket.on('error', (err) => {
      finish({
        inspected: false,
        valid: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        authorizationError: err.message,
      });
    });
  });
}
