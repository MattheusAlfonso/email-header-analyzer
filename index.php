<?php
require_once 'analyzer.php';

$analysis = null;
$raw_header_input = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['email_header'])) {
    $raw_header_input = $_POST['email_header'];
    $analysis = analyzeEmailHeader($raw_header_input);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Projeto 3 - Phishing & Header Security Analyzer</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
    <h2> Analisador de Cabeçalhos & Threat Intel</h2>
    <p>Insira o cabeçalho bruto (raw header) do e-mail suspeito para extração de indicadores de comprometimento (IoCs).</p>

        <form action="index.php" method="POST">
            <div class="form-group">
                <label for="email_header">Cabeçalho do E-mail (Header):</label>
                    <textarea id="email_header" name="email_header" rows="8" placeholder="Cole aqui o cabeçalho bruto recebido (ex: Received: from..., From:..., Return-Path:...)" required><?= htmlspecialchars($raw_header_input, ENT_QUOTES, 'UTF-8') ?></textarea>
</div>
            <button type="submit">Executar Análise de Risco</button>
</form>

        <?php if ($analysis): ?>
            <div class="report-box">
    <h3> Relatório de Triagem de Ameaça</h3>
                
<div class="risk-badge risk-<?= strtolower($analysis['risk_level']) ?>">
                    Nível de Risco: <?= $analysis['risk_level'] ?> (Score: <?= $analysis['score'] ?>/100)
</div>

<div class="details">
    <p><strong>Remetente (From):</strong> <code><?= htmlspecialchars($analysis['from'], ENT_QUOTES, 'UTF-8') ?></code></p>
    <p><strong>Caminho de Retorno (Return-Path):</strong> <code><?= htmlspecialchars($analysis['return_path'], ENT_QUOTES, 'UTF-8') ?></code></p>
    <p><strong>IP de Origem:</strong> <code><?= htmlspecialchars($analysis['ip'], ENT_QUOTES, 'UTF-8') ?></code></p>
    <p><strong>Status SPF:</strong> <span class="badge"><?= $analysis['spf'] ?></span> | <strong>DKIM:</strong> <span class="badge"><?= $analysis['dkim'] ?></span> | <strong>DMARC:</strong> <span class="badge"><?= $analysis['dmarc'] ?></span></p>
</div>

    <?php if (!empty($analysis['flags'])): ?>
<div class="flags-box">
        <h4> Alertas & Indicadores Suspeitos:</h4>
            <ul>
                <?php foreach ($analysis['flags'] as $flag): ?>
                     <li><?= htmlspecialchars($flag, ENT_QUOTES, 'UTF-8') ?></li>
                        <?php endforeach; ?>
</ul>
</div>
<?php endif; ?>
</div>
<?php endif; ?>
</div>
</body>
</html>