<?php

const MAX_HEADER_BYTES = 65536;

// Retorna o valor do PRIMEIRO cabeçalho com esse nome (ancorado no início da linha).
// Sem a âncora ^, "X-Original-From:" seria confundido com "From:".
function headerValue(string $headers, string $name): ?string
{
    if (preg_match('/^' . preg_quote($name, '/') . ':[ \t]*(.*)$/mi', $headers, $m)) {
        return trim($m[1]);
    }
    return null;
}

function extractDomain(?string $address): ?string
{
    if ($address && preg_match('/@([a-z0-9.-]+\.[a-z]{2,})/i', $address, $m)) {
        return strtolower(rtrim($m[1], '.'));
    }
    return null;
}

// "mail.empresa.com" e "empresa.com" são considerados alinhados (mesma organização).
function domainsAligned(string $a, string $b): bool
{
    return $a === $b || str_ends_with($a, '.' . $b) || str_ends_with($b, '.' . $a);
}

function analyzeEmailHeader(string $raw_header): array
{
    $result = [
        'from'        => 'Não identificado',
        'return_path' => 'Não identificado',
        'reply_to'    => 'Não identificado',
        'ip'          => 'Não localizado',
        'spf'         => 'NOT_FOUND',
        'dkim'        => 'NOT_FOUND',
        'dmarc'       => 'NOT_FOUND',
        'score'       => 0,
        'risk_level'  => 'BAIXO',
        'risk_class'  => 'baixo',
        'flags'       => [],
    ];

    // O parsing trabalha com o texto ORIGINAL. O escape para HTML acontece só na exibição
    // (index.php); escapar aqui quebrava o regex e exibia "&lt;" duplicado na tela.
    $header = trim(substr($raw_header, 0, MAX_HEADER_BYTES));
    if ($header === '') {
        return $result;
    }

    // RFC 5322: cabeçalhos longos continuam na linha seguinte iniciada por espaço/tab.
    $header = preg_replace('/\r?\n[ \t]+/', ' ', str_replace("\r\n", "\n", $header));

    $from        = headerValue($header, 'From');
    $return_path = headerValue($header, 'Return-Path');
    $reply_to    = headerValue($header, 'Reply-To');

    if ($from !== null)        $result['from'] = $from;
    if ($return_path !== null) $result['return_path'] = trim($return_path, '<> ');
    if ($reply_to !== null)    $result['reply_to'] = $reply_to;

    // Cada servidor ADICIONA um "Received" no topo; o último da lista é o mais próximo da origem.
    if (preg_match_all('/^Received:.*?\[(\d{1,3}(?:\.\d{1,3}){3})\]/mi', $header, $m)) {
        $result['ip'] = end($m[1]);
    }

    // Os resultados vêm do Authentication-Results do topo, inserido pelo SEU servidor de e-mail.
    // Valores "spf=pass" escritos em outras partes do header podem ter sido forjados pelo remetente.
    $auth = headerValue($header, 'Authentication-Results') ?? '';
    foreach (['spf', 'dkim', 'dmarc'] as $mech) {
        if (preg_match('/\b' . $mech . '=(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b/i', $auth, $m)) {
            $result[$mech] = strtoupper($m[1]);
        }
    }

    $add = function (int $points, string $flag) use (&$result) {
        $result['score'] += $points;
        $result['flags'][] = $flag;
    };

    if ($result['spf'] === 'FAIL') {
        $add(25, 'SPF FAIL: o IP de envio não está autorizado pelo domínio.');
    } elseif (in_array($result['spf'], ['SOFTFAIL', 'NONE', 'PERMERROR'], true)) {
        $add(15, "SPF {$result['spf']}: autorização do remetente fraca ou ausente.");
    }

    if ($result['dkim'] === 'FAIL') {
        $add(25, 'DKIM FAIL: a assinatura não confere (mensagem alterada ou forjada).');
    } elseif (in_array($result['dkim'], ['NONE', 'PERMERROR'], true)) {
        $add(10, "DKIM {$result['dkim']}: mensagem sem assinatura válida.");
    }

    if ($result['dmarc'] === 'FAIL') {
        $add(30, 'DMARC FAIL: o domínio do From não passou na política do próprio dono. Forte indício de spoofing.');
    }

    $from_domain   = extractDomain($from);
    $return_domain = extractDomain($return_path);
    $reply_domain  = extractDomain($reply_to);

    if ($from_domain && $return_domain && !domainsAligned($from_domain, $return_domain)) {
        // Peso moderado: newsletters legítimas (SendGrid, Mailchimp...) também causam essa divergência.
        $add(15, "Divergência: From ({$from_domain}) difere do Return-Path ({$return_domain}).");
    }

    if ($from_domain && $reply_domain && !domainsAligned($from_domain, $reply_domain)) {
        $add(20, "Reply-To ({$reply_domain}) desvia as respostas para um domínio diferente do From ({$from_domain}). Tática comum em BEC/phishing.");
    }

    $result['score'] = min($result['score'], 100);

    if ($result['score'] >= 60) {
        [$result['risk_level'], $result['risk_class']] = ['ALTO', 'alto'];
    } elseif ($result['score'] >= 30) {
        [$result['risk_level'], $result['risk_class']] = ['MÉDIO', 'medio'];
    }

    return $result;
}
