import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

let globalDevices = []; 
let sessionToken = null;

// 서버리스 건망증 해결을 위한 쿠키 파싱 함수
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
        // 1. 등록용 일회용 질문(Challenge) 발급
        if (action === 'generate-reg') {
            const options = await generateRegistrationOptions({
                rpName, rpID,
                userID: new Uint8Array(Buffer.from('admin-user')),
                userName: 'admin',
                attestationType: 'none',
                authenticatorSelection: { authenticatorAttachment: 'platform' },
                excludeCredentials: globalDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' })),
            });
            // ★ Vercel 서버리스 증발을 막기 위해 챌린지를 보안 쿠키에 저장
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 2. 등록 서명 검증 및 공개키 저장
        if (action === 'verify-reg') {
            const { response, deviceName } = req.body;
            const expectedChallenge = cookies.challenge; // 쿠키에서 챌린지 꺼내기
            if (!expectedChallenge) return res.status(400).json({ error: '시간 초과 또는 질문을 잃어버렸습니다.' });

            let verification = await verifyRegistrationResponse({
                response,
                expectedChallenge,
                expectedOrigin,
                expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const { credential } = verification.registrationInfo;
                globalDevices.push({
                    credentialID: credential.id,
                    publicKey: credential.publicKey, 
                    counter: credential.counter,
                    name: deviceName || '새 기기',
                    registeredAt: new Date().toISOString()
                });
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`); // 사용 후 즉시 파기
                return res.status(200).json({ success: true });
            }
            return res.status(400).json({ error: '서명 검증 실패' });
        }

        // 3. 로그인용 일회용 질문(Challenge) 발급
        if (action === 'generate-auth') {
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: globalDevices.map(dev => ({ id: dev.credentialID, type: 'public-key' })),
            });
            res.setHeader('Set-Cookie', `challenge=${options.challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 4. 로그인 서명 검증
        if (action === 'verify-auth') {
            const { response } = req.body;
            const expectedChallenge = cookies.challenge;
            if (!expectedChallenge) return res.status(400).json({ error: '만료되거나 이미 사용된 질문(재사용 차단)입니다.' });

            const device = globalDevices.find(d => d.credentialID === response.id);
            if (!device) return res.status(400).json({ error: '등록되지 않은 기기입니다.' });

            let verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge,
                expectedOrigin,
                expectedRPID: rpID,
                credential: { id: device.credentialID, publicKey: device.publicKey, counter: device.counter }
            });

            if (verification.verified) {
                device.counter = verification.authenticationInfo.newCounter;
                sessionToken = 'secure-session-' + Date.now();
                res.setHeader('Set-Cookie', `challenge=; Path=/; HttpOnly; Max-Age=0`); // 재사용 원천 차단 (T08-C31)
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '로그인 검증 실패' });
        }

        // 5. 비공개 데이터 요청
        if (action === 'get-private-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) {
                return res.status(403).json({ error: '403 Forbidden: 패스키 인증이 필요합니다.' });
            }
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'WebAuthn API를 활용한 B2B SaaS 기업용 비밀번호 없는 사내망 인증 시스템 설계 기획안.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무, 클라우드 아키텍트 직무.' },
                    { title: '스스로 쓰는 회고', content: '보안과 편의성은 반비례한다는 편견을 패스키(Passkey) 기술을 직접 구현하며 깨부수었다.' }
                ],
                devices: globalDevices.map(d => ({ id: d.credentialID, name: d.name, date: d.registeredAt }))
            });
        }

        // 6. 패스키 삭제
        if (action === 'delete-key') {
            const { credentialID } = req.body;
            globalDevices = globalDevices.filter(d => d.credentialID !== credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
