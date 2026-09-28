// 서버는 복잡한 암호학적 검증을 버리고, 사용자가 추가한 기기 ID를 기억(저장)하는 역할만 수행합니다.
let globalDevices = [];
let sessionToken = null;

export default async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const { action } = req.query;

    try {
        // 1. 패스키 등록 (사용자가 프론트에서 만든 기기 ID를 서버에 직접 추가)
        if (action === 'register') {
            const { credentialId, deviceName } = req.body;
            globalDevices.push({
                id: credentialId,
                name: deviceName || '새 기기',
                date: new Date().toISOString()
            });
            return res.status(200).json({ success: true });
        }

        // 2. 패스키 로그인 (프론트에서 넘어온 기기 ID가 등록되어 있는지 확인)
        if (action === 'login') {
            const { credentialId } = req.body;
            const device = globalDevices.find(d => d.id === credentialId);
            
            if (device) {
                sessionToken = 'simple-token-' + Date.now();
                return res.status(200).json({ success: true, token: sessionToken });
            }
            return res.status(400).json({ error: '등록되지 않은 기기입니다.' });
        }

        // 3. 비공개 데이터 전송
        if (action === 'get-data') {
            const token = req.headers.authorization?.split('Bearer ')[1];
            if (token !== sessionToken) return res.status(403).json({ error: '권한 없음' });
            return res.status(200).json({
                privateItems: [
                    { title: '준비 중인 프로젝트 메모', content: '복잡한 라이브러리를 버리고 Native API로 인증 시스템 구현.' },
                    { title: '지원하려는 곳 목록', content: '통신 3사 핵심 인프라 기획 직무.' },
                    { title: '회고', content: '문제 발생 시 과감하게 다른 우회로를 찾는 결단력을 배웠다.' }
                ],
                devices: globalDevices.map(d => ({ id: d.id, name: d.name, date: d.date }))
            });
        }

        // 4. 패스키 삭제
        if (action === 'delete-key') {
            globalDevices = globalDevices.filter(d => d.id !== req.body.credentialID);
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Not found' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
}
