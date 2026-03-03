<?php
// config.php - API para gerenciar configurações centralizadas
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Permitir acesso de qualquer origem (CORS)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Lidar com requisições OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Caminho para o arquivo config.json
$configFile = __DIR__ . '/config.json';

// ===== SE FOR REQUISIÇÃO POST =====
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (!$data || !isset($data['link_download'])) {
        echo json_encode([
            'success' => false, 
            'message' => 'Dados inválidos. Link é obrigatório.'
        ]);
        exit();
    }
    
    $config = [
        'link_download' => $data['link_download'],
        'nome_app' => $data['nome_app'] ?? 'PrecisionBoosterV2',
        'ultima_atualizacao' => date('Y-m-d H:i:s')
    ];
    
    // Tentar salvar
    $success = file_put_contents(
        $configFile, 
        json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    );
    
    if ($success) {
        echo json_encode(['success' => true, 'message' => 'Configuração salva!']);
    } else {
        echo json_encode([
            'success' => false, 
            'message' => 'Erro ao salvar. Permissão de escrita?'
        ]);
    }
    exit();
}

// ===== SE FOR REQUISIÇÃO GET =====
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (file_exists($configFile)) {
        $content = file_get_contents($configFile);
        echo $content;
    } else {
        // Criar arquivo padrão
        $defaultConfig = [
            'link_download' => 'https://www.mediafire.com/file/5584fq6wsix3ymh/PrecisipnBoosterV2.apk/file',
            'nome_app' => 'PrecisionBoosterV2',
            'ultima_atualizacao' => date('Y-m-d H:i:s')
        ];
        
        file_put_contents(
            $configFile, 
            json_encode($defaultConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
        
        echo json_encode($defaultConfig);
    }
    exit();
}

// Se chegar aqui, método não permitido
http_response_code(405);
echo json_encode(['success' => false, 'message' => 'Método não permitido']);
?>
