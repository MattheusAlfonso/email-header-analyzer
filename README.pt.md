[ 🇺🇸 English ](README.md) | [ 🇪🇸 Español ](README.es.md) | [ 🇧🇷 Português ](README.pt.md)

---

# Analisador de Phishing & Cabeçalhos de E-mail (PHP)

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?logo=php&logoColor=white)
![Tema](https://img.shields.io/badge/tema-Triagem%20de%20Phishing-orange)
![Foco](https://img.shields.io/badge/foco-Seguran%C3%A7a%20de%20E--mail-0284c7)

Uma ferramenta de triagem de e-mails suspeitos: cole o cabeçalho bruto e receba os indicadores do remetente, os resultados de SPF / DKIM / DMARC, checagens de alinhamento de domínio e um score de risco de 0 a 100 com a explicação de cada ponto.

Nasceu do meu dia a dia em conscientização e prevenção de phishing: transforma o "esse e-mail parece estranho" em evidência concreta e explicável.

![Preview do Analisador](preview.png)

## O que é verificado

| Indicador | Por que importa | Pontos |
|---|---|---|
| `DMARC=fail` | O domínio do `From` falhou na política do próprio dono. Sinal mais forte de spoofing. | +30 |
| `SPF=fail` | O IP de envio não é autorizado pelo domínio | +25 |
| `SPF=softfail / none / permerror` | Autorização do remetente fraca ou ausente | +15 |
| `DKIM=fail` | A assinatura não confere: mensagem alterada ou forjada | +25 |
| `DKIM=none / permerror` | Mensagem sem assinatura | +10 |
| Domínio do `Reply-To` ≠ domínio do `From` | As respostas são desviadas para o atacante. Tática clássica de BEC / phishing. | +20 |
| Domínio do `Return-Path` ≠ domínio do `From` | Possível spoofing. Peso menor: newsletters legítimas (SendGrid, Mailchimp…) também fazem isso. | +15 |

Score ≥ 60 → **ALTO**, ≥ 30 → **MÉDIO**, abaixo disso **BAIXO**. Subdomínios do mesmo domínio (`mail.empresa.com` / `empresa.com`) são considerados alinhados.

## Decisões de parsing

- **Só o `Authentication-Results` do topo é confiável.** Ele é adicionado pelo *seu* servidor de e-mail. O atacante pode escrever `spf=pass` em qualquer outra parte do cabeçalho que ele controla.
- **Os cabeçalhos são buscados no início da linha** (`^From:`), então `X-Original-From:` não é confundido com `From:`.
- **Cabeçalhos dobrados são desdobrados** (RFC 5322): valores longos que continuam na linha seguinte são lidos corretamente.
- **IP de origem** = o IPv4 do **último** cabeçalho `Received`, já que cada servidor adiciona a sua linha no topo.
- **A entrada é analisada crua e escapada só na saída.** Uma versão anterior escapava antes do parsing, o que quebrava os regex e exibia `&lt;` na tela.

## Segurança da própria ferramenta

A ferramenta processa texto controlado pelo atacante, então também é protegida: todo valor é codificado em HTML na saída, a entrada é limitada a 64 KB e uma Content-Security-Policy restritiva bloqueia qualquer script que tente passar.

## Teste

```text
Return-Path: <billing@secure-pay-update.ru>
Authentication-Results: mx.empresa.com;
       spf=fail smtp.mailfrom=secure-pay-update.ru;
       dkim=none;
       dmarc=fail header.from=paypal.com
Received: from mail.secure-pay-update.ru ([185.220.101.4])
From: "PayPal" <service@paypal.com>
Reply-To: support@secure-pay-update.ru
Subject: Your account has been limited
```

Resultado esperado: risco **ALTO** (score 100), com alertas de SPF, DKIM, DMARC, Reply-To e Return-Path.

## Como executar

Requisito: PHP 8.0+.

```bash
git clone https://github.com/MattheusAlfonso/email-header-analyzer.git
cd email-header-analyzer
php -S localhost:8000
```

Acesse <http://localhost:8000>.

## Próximos passos

- [ ] Extrair URLs do corpo e consultá-las em feeds de threat intel (VirusTotal, URLhaus)
- [ ] Suporte a IPv6 e detecção de IPs privados nos saltos `Received`
- [ ] Detecção de domínios parecidos (`paypa1.com`, punycode)
- [ ] Upload direto de arquivos `.eml`

---
*Parte do meu [portfólio de cibersegurança](https://mattheusalfonso.github.io).*
