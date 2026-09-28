import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

// ★ 핵심: 완전히 새로운 V3 변수를 만들어 서버 메모리를 초기화합니다.
let globalDevicesV3 = []; 
let sessionToken = null;

export default async function handler(req, res) {
    // 강력한 캐시 방지
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const { action } = req.query;
    const rpName = '내 포트폴리오 비공개 영역';
    const rpID = req.headers.host.split(':')[0]; 
    const expectedOrigin = req.headers.origin || `https://${req.headers.host}`;

    try {
        if (action === 'generate-reg') {
            // ★ 에러의 원흉 차단: 정상적인 ID(문자열)를 가진 기기만 필터링해서 보냅니다.
            const validDevices = globalDevicesV3.filter(dev => typeof dev.credentialID === 'string');
            
            const options = await generateRegistrationOptions({
                rpName, rpID,
                userID: new Uint8Array(Buffer.from('portfolio-admin-user')),
                userName: 'admin',
                attestationType: 'none',
                authenticatorSelection: { authenticatorAttachment: 'platform' },
                excludeCredentials: validDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' }))
            });
            
            res.setHeader('Set-Cookie', `my_challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            
            const cookieStr = req.headers.cookie || '';
            const challengeMatch = cookieStr.match(/my_challenge=([^;]+)/);
            const expectedChallenge = challengeMatch ? challengeMatch[1] : null;

            if (!expectedChallenge) return res.status(400).json({ error: '시간 초과: 질문(Challenge) 유실' });

            const verification = await verifyRegistrationResponse({
                response, expectedChallenge, expectedOrigin, expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const regInfo = verification.registrationInfo;
                // 구버전/신버전 라이브러리 상관없이 ID를 무조건 안전한 문자열로 추출
                let credID = regInfo.credential ? regInfo.credential.id : regInfo.credentialID;
                if (credID instanceof Uint8Array) {
                    credID = Buffer.from(credID).toString('base64url').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }

                if (typeof credID === 'string') {
                    globalDevicesV3.push({
                        credentialID: credID,
                        publicKey: regInfo.credential ? regInfo.credential.publicKey : regInfo.credentialPublicKey,
                        counter: regInfo.credential ? regInfo.credential.counter : regInfo.counter,
                        name: deviceName || '가상 기기',
                        registeredAt: new Date().toISOString()
                    });
                }
                res.setHeader('Set-Cookie', `my_challenge=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '서명 검증 실패' });
        }

        if (action === 'generate-auth') {
            const validDevices = globalDevicesV3.filter(dev => typeof dev.credentialID === 'string');
            
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: validDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' })),
            });
            res.setHeader('Set-Cookie', `my_challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        if (action === 'verify-auth') {
            const { response } = req.body;
            const cookieStr = req.headers.cookie || '';
            const challengeMatch = cookieStr.match(/my_challenge=([^;]+)/);
            const expectedChallenge = challengeMatch ? challengeMatch[1] : null;

            if (!expectedChallenge) return res.status(400).json({ error: '로그인 시간 초과' });

            const device = globalDevicesV3.find(d => d.credentialID === response.id);
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
                device.counter = verification.authenticationInfo ? verification.authenticationInfo.newCounter : 0;
                sessionToken = 'secure-token-v3';
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
                devices: globalDevicesV3.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        if (action === 'delete-key') {
            globalDevicesV3 = globalDevicesV3.filter(d => d.credentialID !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
