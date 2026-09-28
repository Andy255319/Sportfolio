import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

// ★ 핵심: 변수명을 V2로 변경하여 Vercel 메모리에 남은 고장 난 캐시를 강제로 파기합니다.
let globalDevicesV2 = []; 
let sessionToken = null;

function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(cookie => {
        let [name, ...rest] = cookie.split('=');
        name = name?.trim();
        if (!name) return;
        const value = rest.join('=').trim();
        if (!value) return;
        list[name] = decodeURIComponent(value);
    });
    return list;
}

export default async function handler(req, res) {
    const { action } = req.query;
    const rpName = '내 포트폴리오 비공개 영역';
    const rpID = req.headers.host.split(':')[0]; 
    const expectedOrigin = req.headers.origin || `https://${rpID}`;
    const cookies = parseCookies(req.headers.cookie);

    try {
        if (action === 'generate-reg') {
            let options;
            const excludeList = globalDevicesV2.map(dev => ({ id: dev.credentialID, type: 'public-key' })).filter(c => c.id);
            
            try { // v10 최신 버전 시도
                options = await generateRegistrationOptions({
                    rpName, rpID,
                    userID: new Uint8Array(Buffer.from('admin-user')),
                    userName: 'admin',
                    attestationType: 'none',
                    authenticatorSelection: { authenticatorAttachment: 'platform' },
                    excludeCredentials: excludeList,
                });
            } catch (err) { // v9 구버전 시도
                options = await generateRegistrationOptions({
                    rpName, rpID,
                    userID: 'admin-user',
                    userName: 'admin',
                    attestationType: 'none',
                    authenticatorSelection: { authenticatorAttachment: 'platform' },
                    excludeCredentials: excludeList,
                });
            }
            
            // 브라우저 에러(reading 'replace') 방지를 위한 강제 문자열 보정
            if (options.user && typeof options.user.id !== 'string') {
                options.user.id = Buffer.from('admin-user').toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            }
            
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            const expectedChallenge = cookies.challenge;
            if (!expectedChallenge) return res.status(400).json({ error: '시간 초과 또는 질문을 잃어버렸습니다.' });

            let verification = await verifyRegistrationResponse({
                response,
                expectedChallenge,
                expectedOrigin,
                expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const regInfo = verification.registrationInfo;
                let credID, pubKey, ctr;
                
                if (regInfo.credential) { // v10
                    credID = regInfo.credential.id;
                    pubKey = regInfo.credential.publicKey;
                    ctr = regInfo.credential.counter;
                } else { // v9
                    credID = Buffer.from(regInfo.credentialID).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                    pubKey = regInfo.credentialPublicKey;
                    ctr = regInfo.counter;
                }

                globalDevicesV2.push({
                    credentialID: credID,
                    publicKey: pubKey, 
                    counter: ctr,
                    name: deviceName || '새 기기',
                    registeredAt: new Date().toISOString()
                });
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '서명 검증 실패' });
        }

        if (action === 'generate-auth') {
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: globalDevicesV2.map(dev => ({ id: dev.credentialID, type: 'public-key' })).filter(c => c.id),
            });
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-auth') {
            const { response } = req.body;
            const expectedChallenge = cookies.challenge;
            if (!expectedChallenge) return res.status(400).json({ error: '만료되거나 이미 사용된 질문입니다.' });

            const device = globalDevicesV2.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '등록되지 않은 기기입니다.' });

            let verification;
            try { // v10
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
                });
            } catch(err) { // v9
                const toBuffer = (b64u) => Buffer.from(b64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    authenticator: { credentialID: toBuffer(device.credentialID), credentialPublicKey: device.publicKey, counter: device.counter }
                });
            }

            if (verification.verified) {
                device.counter = verification.authenticationInfo ? verification.authenticationInfo.newCounter : 0;
                sessionToken = 'secure-session-' + Date.now();
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '로그인 검증 실패' });
        }

        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) {
                return res.status(403).json({ error: '403 Forbidden: 패스키 인증이 필요합니다.' });
            }
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 기업용 비밀번호 없는 사내망 인증 시스템 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무, 클라우드 아키텍트 직무.' },
                    { title: '스스로 쓰는 회고', content: '보안과 편의성은 반비례한다는 편견을 패스키(Passkey) 기술을 구현하며 깨부수었다.' }
                ],
                devices: globalDevicesV2.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        if (action === 'delete-key') {
            const { credentialID } = req.body;
            globalDevicesV2 = globalDevicesV2.filter(d => d.credentialID !== credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
