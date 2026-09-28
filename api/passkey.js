import crypto from 'crypto';
import {
    verifyRegistrationResponse,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

let globalDevicesList = []; 
let sessionToken = null;

// 바이너리 데이터를 안전한 WebAuthn 표준 텍스트로 변환하는 함수
function toBase64Url(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// 안전한 쿠키 추출기
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
    const { action } = req.query;
    const rpName = '내 포트폴리오 비공개 영역';
    const rpID = req.headers.host.split(':')[0]; 
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;
    const cookies = parseCookies(req.headers.cookie);

    try {
        // 1. 등록용 질문 생성 (라이브러리 버그를 피해 순수 수제작 JSON 반환)
        if (action === 'generate-reg') {
            const challengeBuf = crypto.randomBytes(32);
            const challengeB64Url = toBase64Url(challengeBuf);

            const options = {
                challenge: challengeB64Url,
                rp: { name: rpName, id: rpID },
                user: {
                    id: toBase64Url(Buffer.from('admin-user-id')),
                    name: 'admin',
                    displayName: 'admin'
                },
                pubKeyCredParams: [
                    { alg: -7, type: "public-key" }, // ES256
                    { alg: -257, type: "public-key" } // RS256
                ],
                timeout: 60000,
                attestation: "none",
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "preferred"
                },
                excludeCredentials: globalDevicesList.map(dev => ({
                    id: dev.credentialID,
                    type: "public-key"
                }))
            };

            res.setHeader('Set-Cookie', `challenge=${challengeB64Url}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 2. 등록 검증
        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            const expectedChallenge = cookies.challenge;

            if (!expectedChallenge) return res.status(400).json({ error: '시간 초과: 질문(Challenge)이 쿠키에 없습니다.' });

            const verification = await verifyRegistrationResponse({
                response,
                expectedChallenge,
                expectedOrigin,
                expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const regInfo = verification.registrationInfo;
                let credID, pubKey, ctr;
                
                if (regInfo.credential) {
                    credID = regInfo.credential.id;
                    pubKey = regInfo.credential.publicKey;
                    ctr = regInfo.credential.counter;
                } else {
                    credID = toBase64Url(Buffer.from(regInfo.credentialID));
                    pubKey = regInfo.credentialPublicKey;
                    ctr = regInfo.counter;
                }

                globalDevicesList.push({
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

        // 3. 로그인용 질문 생성 (수제작 JSON)
        if (action === 'generate-auth') {
            const challengeBuf = crypto.randomBytes(32);
            const challengeB64Url = toBase64Url(challengeBuf);

            const options = {
                challenge: challengeB64Url,
                rpId: rpID,
                allowCredentials: globalDevicesList.map(dev => ({
                    id: dev.credentialID,
                    type: "public-key"
                })),
                userVerification: "preferred",
                timeout: 60000
            };

            res.setHeader('Set-Cookie', `challenge=${challengeB64Url}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 4. 로그인 서명 검증
        if (action === 'verify-auth') {
            const { response } = req.body;
            const expectedChallenge = cookies.challenge;

            if (!expectedChallenge) return res.status(400).json({ error: '만료된 로그인 질문입니다.' });

            const device = globalDevicesList.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '등록되지 않은 기기입니다.' });

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
                });
            } catch(e) {
                const fromBase64Url = (str) => Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
                verification = await verifyAuthenticationResponse({
                    response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
                    authenticator: { credentialID: fromBase64Url(device.credentialID), credentialPublicKey: device.publicKey, counter: device.counter }
                });
            }

            if (verification.verified) {
                if (verification.authenticationInfo) device.counter = verification.authenticationInfo.newCounter;
                sessionToken = 'secure-session-' + Date.now();
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '인증 실패' });
        }

        // 5. 비공개 데이터 요청
        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) return res.status(403).json({ error: 'Forbidden' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 B2B SaaS 기업용 비밀번호 없는 사내망 인증 시스템 설계 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무, 클라우드 아키텍트 직무.' },
                    { title: '스스로 쓰는 회고', content: '보안과 편의성은 반비례한다는 편견을 패스키(Passkey) 기술을 직접 구현하며 깨부수었다.' }
                ],
                devices: globalDevicesList.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        // 6. 패스키 삭제
        if (action === 'delete-key') {
            globalDevicesList = globalDevicesList.filter(d => d.credentialID !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        console.error("SERVER ERROR:", err);
        return res.status(500).json({ error: err.message });
    }
}
