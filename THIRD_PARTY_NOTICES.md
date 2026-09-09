# Сторонние источники

Код TrafficGuard-auto и исполняемый файл traffic-guard не включены, не скачиваются и не запускаются.
Для определения требований были изучены внешний установщик DonMatteoVPN/TrafficGuard-auto
и документация dotX12/traffic-guard. Реализация этого проекта написана отдельно на Python/nftables.

Внешние данные (все три источника включены):

- https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
- https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
- https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list

Источник и авторство данных: https://github.com/shadow-netlab/traffic-guard-lists
Условия источника: https://github.com/shadow-netlab/traffic-guard-lists/blob/main/LICENSE
Списки не зеркалируются в этом репозитории. Их качество и состав контролируются внешними авторами.
HTTPS защищает передачу, но не от ошибочного или скомпрометированного источника.

Системные зависимости: Python, Linux Netfilter/nftables, systemd. Они устанавливаются отдельно
и сохраняют собственные лицензии. Документация nftables: https://www.netfilter.org/projects/nftables/manpage.html
