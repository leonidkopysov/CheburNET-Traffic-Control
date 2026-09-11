# Обновление до 1.0.1

Для уже установленной программы повторный `install` не нужен. Обновите исполняемый файл,
затем обновите службы через `repair`. Исключения, SSH-порты и ручные блокировки сохраняются.
При включённой фильтрации правила будут заново применены, поэтому счётчики текущей таблицы обнулятся.

Команда ниже скачивает фиксированный релиз, проверяет SHA-256, делает резервную копию файла
и конфигурации, заменяет программу атомарно и запускает восстановление. Операция с резервной копией
и заменой файла выполняется под той же блокировкой, что и команды программы.

```bash
sudo bash <<'CTC_UPDATE'
set -euo pipefail
ctc_download_dir=$(mktemp -d /tmp/ctc-update.XXXXXX)
trap 'rm -rf -- "$ctc_download_dir"' EXIT
cd "$ctc_download_dir"
curl -fsSLo cheburnet-traffic-control.py \
  https://raw.githubusercontent.com/leonidkopysov/CheburNET-Traffic-Control/v1.0.1/cheburnet-traffic-control.py
curl -fsSLo SHA256SUMS \
  https://raw.githubusercontent.com/leonidkopysov/CheburNET-Traffic-Control/v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS
test "$(python3 ./cheburnet-traffic-control.py --version)" = '1.0.1'
(
  flock -x 9
  test -f /usr/local/bin/cheburnet-traffic-control
  test -f /var/lib/cheburnet-traffic-control/state.json
  if test -e /var/lib/cheburnet-traffic-control/pending; then
    echo 'Предыдущее включение не завершено. Выполните ctc off и повторите обновление.'
    exit 1
  fi
  ctc_backup_dir=$(mktemp -d /root/ctc-backup.XXXXXX)
  cp -a /usr/local/bin/cheburnet-traffic-control "$ctc_backup_dir/"
  cp -a /var/lib/cheburnet-traffic-control "$ctc_backup_dir/"
  echo "Резервная копия: $ctc_backup_dir"
  install -o root -g root -m 0755 cheburnet-traffic-control.py \
    /usr/local/bin/.cheburnet-traffic-control.new
  mv -f /usr/local/bin/.cheburnet-traffic-control.new /usr/local/bin/cheburnet-traffic-control
) 9>/run/cheburnet-traffic-control.lock
/usr/local/bin/cheburnet-traffic-control repair --yes
/usr/local/bin/ctc --version
/usr/local/bin/ctc s
CTC_UPDATE
```

После успешного обновления `ctc --version` показывает `1.0.1`. Откройте меню командой `sudo ctc`.
Если фильтрация была выключена, она останется выключенной: включите её через `sudo ctc on`, когда готовы.
Если была включена, отдельное выключение и включение для обновления не требуются.

В релизе включение выполняется одним действием; после `ctc on` подтверждать его отдельной командой не нужно.
Старые служебные имена сохранены для совместимости существующих установок.

Если `repair` сообщает об ошибке, сохраните её вывод и путь резервной копии. При необходимости можно
вернуть прежний исполняемый файл из этой папки, затем выполнить его `repair --yes` для восстановления
соответствующих служб. Не удаляйте `state.json` для обхода ошибки повторной установки.
