import crypto from 'crypto';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

let globalDevices = [];
let sessionToken = null;

// 안전한 Base64URL 변환 함수
function safeBase64Url(bytesLength) {
    return crypto.randomBytes(bytesLength).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    
    const action = req.query.action;
    const rpID = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;
    
    let cookieChallenge = null;
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/passkey_chl=([^;]+)/);
        if (match) cookieChallenge = match[1];
    }

    try {
        if (action === 'generate-reg') {
            const challenge = safeBase64Url(32);
            const userId = safeBase64Url(16);

            const options = {
                challenge: challenge,
                rp: { name: '네트워크 엔지니어 포트폴리오', id: rpID },
                user: {
                    id: userId,
                    name: 'admin',
                    displayName: '관리자'
                },
                pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
                timeout: 60000,
                attestation: "none",
                authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "preferred" },
                excludeCredentials: globalDevices.map(d => ({ id: d.credentialID, type: "public-key" }))
            };

            res.setHeader('Set-Cookie', `passkey_chl=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            if (!cookieChallenge) return res.status(400).json({ error: '질문 쿠키 누락' });

            const verification = await verifyRegistrationResponse({
                response, expectedChallenge: cookieChallenge, expectedOrigin, expectedRPID: rpID,
            });

            if (verification.verified) {
                const regInfo = verification.registrationInfo;
                let credID = regInfo.credential ? regInfo.credential.id : regInfo.credentialID;
                if (typeof credID !== 'string') {
                    credID = Buffer.from(credID).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }

                globalDevices.push({
                    credentialID: credID,
                    publicKey: regInfo.credential ? regInfo.credential.publicKey : regInfo.credentialPublicKey,
                    counter: regInfo.credential ? regInfo.credential.counter : regInfo.counter,
                    name: deviceName || '가상 기기',
                    registeredAt: new Date().toISOString()
                });
                res.setHeader('Set-Cookie', `passkey_chl=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '검증 실패' });
        }

        if (action === 'generate-auth') {
            const challenge = safeBase64Url(32);
            const options = {
                challenge: challenge,
                rpId: rpID,
                allowCredentials: globalDevices.map(d => ({ id: d.credentialID, type: "public-key" })),
                userVerification: "preferred",
                timeout: 60000
            };

            res.setHeader('Set-Cookie', `passkey_chl=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-auth') {
            const { response } = req.body;
            if (!cookieChallenge) return res.status(400).json({ error: '로그인 질문 누락' });

            const device = globalDevices.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '미등록 기기' });

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge: cookieChallenge, expectedOrigin, expectedRPID: rpID,
                    credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
                });
            } catch(e) {
                const toBuf = (str) => Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge: cookieChallenge, expectedOrigin, expectedRPID: rpID,
                    authenticator: { credentialID: toBuf(device.credentialID), credentialPublicKey: device.publicKey, counter: device.counter }
                });
            }

            if (verification.verified) {
                if (verification.authenticationInfo) device.counter = verification.authenticationInfo.newCounter;
                sessionToken = safeBase64Url(16);
                res.setHeader('Set-Cookie', `passkey_chl=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '인증 실패' });
        }

        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (token !== sessionToken) return res.status(403).json({ error: 'Forbidden' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무.' },
                    { title: '회고', content: '보안과 편의성은 반비례한다는 편견을 패스키를 통해 깼다.' }
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
