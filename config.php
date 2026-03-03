<?php
// config.php - API para gerenciar configurações centralizadas

// Permitir acesso de qualquer origem (CORS)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Lidar com requisições OPTIONS (pré-verificação CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Caminho para o arquivo config.json (na mesma pasta)
$configFile = __DIR__ . '/config.json';

// ===== SE FOR REQUISIÇÃO POST (salvar configuração) =====
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Pegar dados enviados
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    // Validar dados
    if (!$data || !isset($data['link_download'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'message' => 'Dados inválidos. Link é obrigatório.'
        ]);
        exit();
    }
    
    // Preparar configuração para salvar
    $config = [
        'link_download' => $data['link_download'],
        'nome_app' => $data['nome_app'] ?? 'PrecisionBoosterV2',
        'ultima_atualizacao' => date('Y-m-d H:i:s')
    ];
    
    // Salvar no arquivo config.json
    $success = file_put_contents(
        $configFile, 
        json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    );
    
    if ($success) {
        echo json_encode([
            'success' => true, 
            'message' => 'Configuração salva com sucesso!'
        ]);
    } else {
        http_response_code(500);
        echo json_encode([
            'success' => false, 
            'message' => 'Erro ao salvar arquivo. Verifique permissões.'
        ]);
    }
    
    exit();
}

// ===== SE FOR REQUISIÇÃO GET (ler configuração) =====
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Verificar se o arquivo existe
    if (file_exists($configFile)) {
        // Ler e retornar o JSON
        $content = file_get_contents($configFile);
        echo $content;
    } else {
        // Arquivo não existe, retornar configuração padrão
        $defaultConfig = [
            'link_download' => 'https://www.mediafire.com/file/5584fq6wsix3ymh/PrecisipnBoosterV2.apk/file',
            'nome_app' => 'PrecisionBoosterV2',
            'ultima_atualizacao' => date('Y-m-d H:i:s')
        ];
        
        // Salvar configuração padrão
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
echo json_encode([
    'success' => false, 
    'message' => 'Método não permitido'
]);
?>
