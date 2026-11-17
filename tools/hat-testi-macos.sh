#!/bin/bash
# macOS hat testi: `sondpi dev` proxy'si üzerinden engelli adlara TLS, popüler sitelerde bozulma
# denetimi, Cloudflare IPv4'e bağlantı güvenilirliği ve indirme hızı. Sistem ayarına dokunmaz.
# Kullanım: önce başka bir terminalde `sondpi dev --port 18642`, sonra: tools/hat-testi-macos.sh [N]
PROXY=${PROXY:-http://127.0.0.1:18642}
N=${1:-30}

code() { curl -sS -o /dev/null -w "%{http_code} %{time_total}" --max-time 15 "$@" 2>/dev/null || true; }

echo "== Engelli adlar, proxy üzerinden ($N deneme)"
for h in discord.com gateway.discord.gg cdn.discordapp.com www.roblox.com; do
  ok=0; t=""
  for i in $(seq 1 "$N"); do
    r=$(code -x "$PROXY" "https://$h/"); c=${r%% *}
    [ "$c" != "000" ] && [ -n "$c" ] && ok=$((ok+1))
    t="$t ${r##* }"
  done
  med=$(echo $t | tr ' ' '\n' | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  echo "$h: $ok/$N (ortanca ${med}s)"
done

echo "== Engelli adlar, proxy olmadan (karşılaştırma, 3 deneme)"
for h in discord.com www.roblox.com; do
  ok=0; for i in 1 2 3; do r=$(code --max-time 6 "https://$h/"); [ "${r%% *}" != "000" ] && ok=$((ok+1)); done
  echo "$h: $ok/3"
done

echo "== Popüler siteler, proxy üzerinden (bozulma denetimi)"
for h in www.google.com www.apple.com github.com www.microsoft.com www.youtube.com www.wikipedia.org \
         www.amazon.com x.com www.cloudflare.com www.instagram.com www.whatsapp.com www.netflix.com \
         www.twitch.tv www.reddit.com open.spotify.com www.linkedin.com www.bing.com www.icloud.com \
         store.steampowered.com www.trendyol.com www.hepsiburada.com www.sahibinden.com; do
  r=$(code -x "$PROXY" "https://$h/"); echo "$h: ${r%% *} ${r##* }s"
done
echo "== Düz HTTP"
for h in discord.com example.com; do r=$(code -x "$PROXY" "http://$h/"); echo "http://$h: ${r%% *}"; done
