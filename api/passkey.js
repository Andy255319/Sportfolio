import crypto from 'crypto';

let globalDevices = [];
let sessionToken = null;

export default async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const { action } = req.query;

    try {
        // 1. 등록용 데이터 및 난수(Challenge) 생성
        if (action === 'generate-reg') {
            const challenge = crypto.randomBytes(32).toString('base64url');
            const userId = crypto.randomBytes(16).toString('base64url');

            const options = {
                challenge: challenge,
                rp: { name: '네트워크 엔지니어 포트폴리오', id: req.headers.host.split(':')[0] },
                user: { id: userId, name: 'admin', displayName: '관리자' },
                pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
                timeout: 60000,
                attestation: "none",
                // ★ 핵심: 기기 내장(platform) 강제를 풀고, 인증이나 신뢰 여부와 상관없이 등록 가능하도록 개방
                authenticatorSelection: { 
                    userVerification: "discouraged" 
                }
            };

            res.setHeader('Set-Cookie', `passkey_chl=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 2. 등록 정보 저장 (사용자가 직접 추가)
        if (action === 'register') {
            const { credentialId, deviceName } = req.body;
            if (!credentialId) return res.status(400).json({ error: '인증서 ID가 없습니다.' });

            // 중복 등록 방지 체크 후 추가
            if (!globalDevices.some(d => d.id === credentialId)) {
                globalDevices.push({
                    id: credentialId,
                    name: deviceName || `등록 기기 ${globalDevices.length + 1}`,
                    date: new Date().toISOString()
                });
            }
            res.setHeader('Set-Cookie', `passkey_chl=; Path=/; HttpOnly; Max-Age=0`);
            return res.status(200).json({ success: true });
        }

        // 3. 로그인용 난수 생성
        if (action === 'generate-auth') {
            const challenge = crypto.randomBytes(32).toString('base64url');
            const options = {
                challenge: challenge,
                rpId: req.headers.host.split(':')[0],
                allowCredentials: globalDevices.map(dev => ({ id: dev.id, type: "public-key" })),
                userVerification: "discouraged",
                timeout: 60000
            };

            res.setHeader('Set-Cookie', `passkey_chl=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 4. 로그인 검증
        if (action === 'login') {
            const { credentialId } = req.body;
            const device = globalDevices.find(d => d.id === credentialId);
            
            if (device) {
                sessionToken = 'token-' + crypto.randomBytes(16).toString('hex');
                res.setHeader('Set-Cookie', `passkey_chl=; Path=/; HttpOnly; Max-Age=0`);
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '등록되지 않은 기기입니다.' });
        }

        // 5. 비공개 데이터 제공
        if (action === 'get-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) return res.status(403).json({ error: '권한 없음' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: 'crypto 모듈을 활용한 유연한 패스키 인증 시스템 구현 완료.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무.' },
                    { title: '회고', content: '하드웨어 및 환경 제약을 극복하고 사용자 중심의 인증 우회로를 설계함.' }
                ],
                devices: globalDevices.map(d => ({ id: d.id, name: d.name, date: d.date }))
            });
        }

        // 6. 기기 삭제
        if (action === 'delete-key') {
            globalDevices = globalDevices.filter(d => d.id !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
