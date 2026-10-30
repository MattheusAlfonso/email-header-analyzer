<?php
require_once 'analyzer.php';

header("Content-Security-Policy: default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$analysis = null;
$raw_header_input = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['email_header'])) {
    $raw_header_input = substr((string)$_POST['email_header'], 0, MAX_HEADER_BYTES);
    $analysis = analyzeEmailHeader($raw_header_input);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Projeto 3 - Phishing & Header Security Analyzer</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
    <h2> Analisador de Cabeçalhos & Threat Intel</h2>
    <p>Insira o cabeçalho bruto (raw header) do e-mail suspeito para extração de indicadores de comprometimento (IoCs).</p>

        <form action="index.php" method="POST">
            <div class="form-group">
                <label for="email_header">Cabeçalho do E-mail (Header):</label>
                <textarea id="email_header" name="email_header" rows="8" maxlength="<?= MAX_HEADER_BYTES ?>" placeholder="Cole aqui o cabeçalho bruto recebido (ex: Received: from..., From:..., Return-Path:...)" required><?= e($raw_header_input) ?></textarea>
            </div>
            <button type="submit">Executar Análise de Risco</button>
        </form>

        <?php if ($analysis): ?>
            <div class="report-box">
                <h3> Relatório de Triagem de Ameaça</h3>

                <div class="risk-badge risk-<?= e($analysis['risk_class']) ?>">
                    Nível de Risco: <?= e($analysis['risk_level']) ?> (Score: <?= (int)$analysis['score'] ?>/100)
                </div>

                <div class="details">
                    <p><strong>Remetente (From):</strong> <code><?= e($analysis['from']) ?></code></p>
                    <p><strong>Caminho de Retorno (Return-Path):</strong> <code><?= e($analysis['return_path']) ?></code></p>
                    <p><strong>Responder para (Reply-To):</strong> <code><?= e($analysis['reply_to']) ?></code></p>
                    <p><strong>IP de Origem:</strong> <code><?= e($analysis['ip']) ?></code></p>
                    <p><strong>Status SPF:</strong> <span class="badge"><?= e($analysis['spf']) ?></span> | <strong>DKIM:</strong> <span class="badge"><?= e($analysis['dkim']) ?></span> | <strong>DMARC:</strong> <span class="badge"><?= e($analysis['dmarc']) ?></span></p>
                </div>

                <?php if (!empty($analysis['flags'])): ?>
                    <div class="flags-box">
                        <h4> Alertas & Indicadores Suspeitos:</h4>
                        <ul>
                            <?php foreach ($analysis['flags'] as $flag): ?>
                                <li><?= e($flag) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
