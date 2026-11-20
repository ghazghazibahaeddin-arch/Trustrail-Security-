import crypto from 'node:crypto';

export interface AwsCredentialsInput {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
}

export interface AwsStsIdentityResult {
  ok: boolean;
  httpStatus: number;
  account?: string;
  arn?: string;
  userId?: string;
  region: string;
  errorCode?: string;
  errorMessage?: string;
}

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function sha256Hex(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function getSignatureKey(secretKey: string, dateStamp: string, regionName: string, serviceName: string): Buffer {
  const kDate = hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, regionName);
  const kService = hmacSha256(kRegion, serviceName);
  return hmacSha256(kService, 'aws4_request');
}

function extractXmlTag(xml: string, tag: string): string | undefined {
  const match = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
  return match?.[1]?.trim();
}

/**
 * Executes a real AWS SigV4 signed STS GetCallerIdentity request without external SDK bloat.
 */
export async function verifyAwsStsCallerIdentity(
  creds: AwsCredentialsInput
): Promise<AwsStsIdentityResult> {
  const region = (creds.region || 'us-east-1').trim();
  const service = 'sts';
  const host = `sts.${region}.amazonaws.com`;
  const endpoint = `https://${host}/`;
  const method = 'POST';
  const payload = 'Action=GetCallerIdentity&Version=2011-06-15';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(payload);

  const headerEntries: Array<[string, string]> = [
    ['content-type', 'application/x-www-form-urlencoded; charset=utf-8'],
    ['host', host],
    ['x-amz-date', amzDate],
  ];
  if (creds.sessionToken) {
    headerEntries.push(['x-amz-security-token', creds.sessionToken]);
  }
  headerEntries.sort((a, b) => a[0].localeCompare(b[0]));

  const canonicalHeaders = headerEntries.map(([k, v]) => `${k}:${v}\n`).join('');
  const signedHeaders = headerEntries.map(([k]) => k).join(';');

  const canonicalRequest = [
    method,
    '/',
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = getSignatureKey(creds.secretAccessKey, dateStamp, region, service);
  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(stringToSign, 'utf8')
    .digest('hex');

  const authorization = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const fetchHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
    Host: host,
    'X-Amz-Date': amzDate,
    Authorization: authorization,
  };
  if (creds.sessionToken) {
    fetchHeaders['X-Amz-Security-Token'] = creds.sessionToken;
  }

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: fetchHeaders,
    body: payload,
    signal: AbortSignal.timeout(8000),
  });

  const bodyXml = await res.text();
  if (!res.ok) {
    return {
      ok: false,
      httpStatus: res.status,
      region,
      errorCode: extractXmlTag(bodyXml, 'Code') || `HTTP_${res.status}`,
      errorMessage: extractXmlTag(bodyXml, 'Message') || 'AWS STS authentication failed.',
    };
  }

  return {
    ok: true,
    httpStatus: res.status,
    region,
    account: extractXmlTag(bodyXml, 'Account'),
    arn: extractXmlTag(bodyXml, 'Arn'),
    userId: extractXmlTag(bodyXml, 'UserId'),
  };
}
