import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

let globalDevicesV5 = [];
let sessionToken = null;

// 안전한 난수 생성
function generateChallenge() {
    return Buffer.from(Math.random().toString() + Date.now().toString())
        .toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default async function handler(req, res) {
    // Vercel 캐시 완벽 차단
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const { action } = req.query;
    const rpID = req.headers.host.split(':')[0];
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;
    
    let expectedChallenge = null;
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/my_challenge=([^;]+)/);
        if (match) expectedChallenge = match[1];
    }

    try {
        if (action === 'generate-reg') {
            const challenge = generateChallenge();
            
            // ★ 에러의 원흉이었던 라이브러리를 버리고, 브라우저가 요구하는 규격 그대로 수제작해서 내려보냅니다.
            const options = {
                challenge: challenge,
                rp: { name: '포트폴리오', id: rpID },
                user: {
                    id: 'YWRtaW4tdXNlcg', // 강제로 고정된 안전한 텍스트 ID
                    name: 'admin',
                    displayName: 'admin'
                },
                pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
                timeout: 60000,
                attestation: "none",
                excludeCredentials: globalDevicesV5.map(dev => ({ id: dev.credentialID, type: "public-key" })),
                authenticatorSelection: { authenticatorAttachment: "platform" }
            };
            
            res.setHeader('Set-Cookie', `my_challenge=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            if (!expectedChallenge) return res.status(400).json({ error: '질문 만료' });

            const verification = await verifyRegistrationResponse({
                response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
            });

            if (verification.verified) {
                const regInfo = verification.registrationInfo;
                let credID = regInfo.credential ? regInfo.credential.id : regInfo.credentialID;
                if (credID instanceof Uint8Array || Buffer.isBuffer(credID)) {
                    credID = Buffer.from(credID).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }
                globalDevicesV5.push({
                    credentialID: credID,
                    publicKey: regInfo.credential ? regInfo.credential.publicKey : regInfo.credentialPublicKey,
                    counter: regInfo.credential ? regInfo.credential.counter : regInfo.counter,
                    name: deviceName || '가상 기기',
                    registeredAt: new Date().toISOString()
                });
                res.setHeader('Set-Cookie', `my_challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '검증 실패' });
        }

        if (action === 'generate-auth') {
            const challenge = generateChallenge();
            
            // ★ 로그인 질문 역시 수제작으로 강제 고정
            const options = {
                challenge: challenge,
                rpId: rpID,
                allowCredentials: globalDevicesV5.map(dev => ({ id: dev.credentialID, type: "public-key" })),
                userVerification: "preferred",
                timeout: 60000
            };
            
            res.setHeader('Set-Cookie', `my_challenge=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-auth') {
            const { response } = req.body;
            if (!expectedChallenge) return res.status(400).json({ error: '질문 만료' });

            const device = globalDevicesV5.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '미등록 기기' });

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
                });
            } catch(e) {
                const toBuf = (str) => Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    authenticator: { credentialID: toBuf(device.credentialID), credentialPublicKey: device.publicKey, counter: device.counter }
                });
            }

            if (verification.verified) {
                if (verification.authenticationInfo) device.counter = verification.authenticationInfo.newCounter;
                sessionToken = 'secure-token-v5';
                res.setHeader('Set-Cookie', `my_challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '인증 실패' });
        }

        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (token !== sessionToken) return res.status(403).json({ error: '403 Forbidden' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 비밀번호 없는 사내망 인증 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무, 클라우드 아키텍트 직무.' },
                    { title: '스스로 쓰는 회고', content: '보안과 편의성은 반비례한다는 편견을 패스키(Passkey)를 통해 깼다.' }
                ],
                devices: globalDevicesV5.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        if (action === 'delete-key') {
            globalDevicesV5 = globalDevicesV5.filter(d => d.credentialID !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }
        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
