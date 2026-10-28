<?php

function analyzeEmailHeader($raw_header) {
    // Sanitização inicial do input
    $header = htmlspecialchars(trim($raw_header), ENT_QUOTES, 'UTF-8');
    $result = [
        'from' => 'Não identificado',
        'return_path' => 'Não identificado',
        'ip' => 'Não localizado',
        'spf' => 'NOT_FOUND',
        'dkim' => 'NOT_FOUND',
        'dmarc' => 'NOT_FOUND',
        'score' => 0,
        'risk_level' => 'BAIXO',
        'flags' => []
];

    if (empty($header)) {
        return $result;
    }
    if (preg_match('/From:\s*(.*?)(?=\r|\n|$)/i', $header, $matches)) {
        $result['from'] = trim($matches[1]);
}
    if (preg_match('/Return-Path:\s*<?([^>\r\n]+)>?/i', $header, $matches)) {
        $result['return_path'] = trim($matches[1]);
    }
    if (preg_match_all('/Received:\s*from.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/i', $header, $matches)) {
    $ips = $matches[1];
    $result['ip'] = end($ips);
    }

if (preg_match('/spf=(pass|fail|softfail|neutral|none)/i', $header, $matches)) {
    $result['spf'] = strtoupper($matches[1]);
    }
if (preg_match('/dkim=(pass|fail|neutral|none)/i', $header, $matches)) {
    $result['dkim'] = strtoupper($matches[1]);
}
if (preg_match('/dmarc=(pass|fail|none)/i', $header, $matches)) {
    $result['dmarc'] = strtoupper($matches[1]);
 }
    
if (in_array($result['spf'], ['FAIL', 'SOFTFAIL', 'NONE'])) {
    $result['score'] += 30;
    $result['flags'][] = "Falha ou ausência de validação SPF ({$result['spf']}).";
 }
if (in_array($result['dkim'], ['FAIL', 'NONE'])) {
    $result['score'] += 30;
    $result['flags'][] = "Assinatura DKIM inválida ou ausente ({$result['dkim']}).";
}
    if ($result['from'] !== 'Não identificado' && $result['return_path'] !== 'Não identificado') {
        preg_match('/@([\w.-]+)/', $result['from'], $from_domain);
        preg_match('/@([\w.-]+)/', $result['return_path'], $return_domain);
        
if (isset($from_domain[1]) && isset($return_domain[1])) {
    if (strtolower($from_domain[1]) !== strtolower($return_domain[1])) {
         $result['score'] += 40;
         $result['flags'][] = "Divergência detectada: Domínio 'From' ({$from_domain[1]}) difere do 'Return-Path' ({$return_domain[1]}). Pode indicar Spoofing!";
}
}
}
if ($result['score'] >= 60) {
        $result['risk_level'] = 'ALTO';
} elseif ($result['score'] >= 30) {
        $result['risk_level'] = 'MÉDIO';
} else {
        $result['risk_level'] = 'BAIXO';
    }
return $result;
}
?>