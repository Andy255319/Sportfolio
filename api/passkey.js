import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

let globalDevices = [];
let sessionToken = null;

function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(cookie => {
        let [name, ...rest] = cookie.split('=');
        name = name?.trim();
        if (!name) return;
        list[name] = decodeURIComponent(rest.join('=').trim());
    });
    return list;
}

export default async function handler(req, res) {
    // ★ 핵심: Vercel의 캐시를 강제로 무력화하여 고장 난 옛날 데이터를 보내지 못하게 막음
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const { action } = req.query;
    const rpName = '내 포트폴리오 비공개 영역';
    const rpID = req.headers.host.split(':')[0];
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;
    const cookies = parseCookies(req.headers.cookie);

    try {
        if (action === 'generate-reg') {
            const options = await generateRegistrationOptions({
                rpName, rpID,
                userID: new Uint8Array(Buffer.from('admin123')),
                userName: 'admin',
                attestationType: 'none',
                authenticatorSelection: { authenticatorAttachment: 'platform' },
                excludeCredentials: globalDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' }))
            });
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            const expectedChallenge = cookies.challenge;
            if (!expectedChallenge) return res.status(400).json({ error: '질문(Challenge) 만료' });

            const verification = await verifyRegistrationResponse({
                response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const { credential } = verification.registrationInfo;
                globalDevices.push({
                    credentialID: credential.id,
                    publicKey: credential.publicKey,
                    counter: credential.counter,
                    name: deviceName || '가상 기기',
                    registeredAt: new Date().toISOString()
                });
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '검증 실패' });
        }

        if (action === 'generate-auth') {
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: globalDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' })),
            });
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-auth') {
            const { response } = req.body;
            const expectedChallenge = cookies.challenge;
            if (!expectedChallenge) return res.status(400).json({ error: '질문 만료' });

            const device = globalDevices.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '미등록 기기' });

            const verification = await verifyAuthenticationResponse({
                response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
            });

            if (verification.verified) {
                device.counter = verification.authenticationInfo.newCounter;
                sessionToken = 'secure-token-123';
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '인증 실패' });
        }

        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (token !== sessionToken) return res.status(403).json({ error: 'Forbidden' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 비밀번호 없는 사내망 인증 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무, 클라우드 아키텍트 직무.' },
                    { title: '스스로 쓰는 회고', content: '보안과 편의성은 반비례한다는 편견을 패스키(Passkey)를 통해 깼다.' }
                ],
                devices: globalDevices.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        if (action === 'delete-key') {
            globalDevices = globalDevices.filter(d => d.credentialID !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
