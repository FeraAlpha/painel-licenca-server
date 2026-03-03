<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

$configFile = __DIR__ . '/config.json';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (file_exists($configFile)) {
        echo file_get_contents($configFile);
    } else {
        $default = [
            'link_download' => 'https://www.mediafire.com/file/5584fq6wsix3ymh/PrecisipnBoosterV2.apk/file',
            'nome_app' => 'PrecisionBoosterV2',
            'ultima_atualizacao' => date('Y-m-d H:i:s')
        ];
        file_put_contents($configFile, json_encode($default, JSON_PRETTY_PRINT));
        echo json_encode($default);
    }
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if ($data && isset($data['link_download'])) {
        $config = [
            'link_download' => $data['link_download'],
            'nome_app' => $data['nome_app'] ?? 'PrecisionBoosterV2',
            'ultima_atualizacao' => date('Y-m-d H:i:s')
        ];
        
        file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Dados inválidos']);
    }
    exit();
}
?>
