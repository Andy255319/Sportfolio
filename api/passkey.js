import crypto from 'crypto';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

// 임시 데이터베이스 역할
let globalDevicesList = [];
let sessionToken = null;

// 쿠키 파싱 함수
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
    // Vercel의 악성 캐시를 완벽하게 무력화
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const { action } = req.query;
    const rpName = '내 포트폴리오 비공개 영역';
    const rpID = req.headers.host.split(':')[0];
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;
    const cookies = parseCookies(req.headers.cookie);

    try {
        // 1. 등록용 질문 생성 (crypto 모듈로 직접 안전한 문자열 생성)
        if (action === 'generate-reg') {
            // 외부 라이브러리 대신 crypto를 사용해 완벽한 Base64URL 규격의 챌린지 생성
            const challenge = crypto.randomBytes(32).toString('base64url');
            const userId = crypto.randomBytes(16).toString('base64url');

            const options = {
                challenge: challenge,
                rp: { name: rpName, id: rpID },
                user: {
                    id: userId,
                    name: 'admin',
                    displayName: '관리자'
                },
                pubKeyCredParams: [
                    { alg: -7, type: "public-key" },  // ES256
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

            res.setHeader('Set-Cookie', `secure_challenge=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 2. 등록 서명 검증
        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            const expectedChallenge = cookies.secure_challenge;

            if (!expectedChallenge) {
                return res.status(400).json({ error: '시간 초과: 질문(Challenge) 쿠키가 만료되었습니다.' });
            }

            const verification = await verifyRegistrationResponse({
                response,
                expectedChallenge,
                expectedOrigin,
                expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const regInfo = verification.registrationInfo;
                let credID = regInfo.credential ? regInfo.credential.id : regInfo.credentialID;
                
                // 버퍼 형태일 경우 강제 문자열 변환
                if (typeof credID !== 'string') {
                    credID = Buffer.from(credID).toString('base64url');
                }

                globalDevicesList.push({
                    credentialID: credID,
                    publicKey: regInfo.credential ? regInfo.credential.publicKey : regInfo.credentialPublicKey,
                    counter: regInfo.credential ? regInfo.credential.counter : regInfo.counter,
                    name: deviceName || '가상 기기',
                    registeredAt: new Date().toISOString()
                });
                
                res.setHeader('Set-Cookie', `secure_challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '등록 검증에 실패했습니다.' });
        }

        // 3. 로그인용 질문 생성 (crypto 모듈 활용)
        if (action === 'generate-auth') {
            const challenge = crypto.randomBytes(32).toString('base64url');

            const options = {
                challenge: challenge,
                rpId: rpID,
                allowCredentials: globalDevicesList.map(dev => ({
                    id: dev.credentialID,
                    type: "public-key"
                })),
                userVerification: "preferred",
                timeout: 60000
            };

            res.setHeader('Set-Cookie', `secure_challenge=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 4. 로그인 서명 검증
        if (action === 'verify-auth') {
            const { response } = req.body;
            const expectedChallenge = cookies.secure_challenge;

            if (!expectedChallenge) return res.status(400).json({ error: '로그인 질문이 만료되었습니다.' });

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
                // crypto를 이용해 예측 불가능한 세션 토큰 발급
                sessionToken = crypto.randomBytes(32).toString('hex');
                res.setHeader('Set-Cookie', `secure_challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '로그인 검증 실패' });
        }

        // 5. 비공개 데이터 요청 (토큰 검증)
        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) return res.status(403).json({ error: 'Forbidden: 권한이 없습니다.' });
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
        console.error("서버 에러:", err);
        return res.status(500).json({ error: err.message });
    }
}
