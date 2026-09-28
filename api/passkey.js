import crypto from 'crypto';

let globalDevices = [];
let userAccounts = []; // 아이디/비밀번호 계정 저장소
let sessionToken = null;

export default async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const { action } = req.query;

    try {
        // 1. 패스키 등록용 데이터 생성
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
                authenticatorSelection: { userVerification: "discouraged" }
            };

            res.setHeader('Set-Cookie', `passkey_chl=${challenge}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`);
            return res.status(200).json(options);
        }

        // 2. 패스키 등록
        if (action === 'register') {
            const { credentialId, deviceName } = req.body;
            if (!credentialId) return res.status(400).json({ error: '인증서 ID가 없습니다.' });

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

        // 3. 패스키 로그인용 난수 생성
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

        // 4. 패스키 로그인 검증
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

        // 5. 아이디/비밀번호 회원가입
        if (action === 'register-pw') {
            const { username, password } = req.body;
            if (!username || !password) return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요.' });

            if (userAccounts.some(u => u.username === username)) {
                return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
            }

            userAccounts.push({ username, password });
            return res.status(200).json({ success: true });
        }

        // 6. 아이디/비밀번호 로그인
        if (action === 'login-pw') {
            const { username, password } = req.body;
            const account = userAccounts.find(u => u.username === username && u.password === password);

            if (account) {
                sessionToken = 'token-' + crypto.randomBytes(16).toString('hex');
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' });
        }

        // 7. 비공개 데이터 제공
        if (action === 'get-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (!token || token !== sessionToken) return res.status(403).json({ error: '권한 없음' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: '패스키 및 아이디/비밀번호 다중 인증 시스템 구현 완료.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무.' },
                    { title: '회고', content: '사용자의 편의성을 위해 다양한 인증 방식을 병행 지원하도록 설계함.' }
                ],
                devices: globalDevices.map(d => ({ id: d.id, name: d.name, date: d.date })),
                accounts: userAccounts.map(u => ({ username: u.username }))
            });
        }

        // 8. 기기 삭제
        if (action === 'delete-key') {
            globalDevices = globalDevices.filter(d => d.id !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
