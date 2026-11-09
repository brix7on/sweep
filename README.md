<a id="english"></a>

# sweep

**English** · [Русский](#russian)

One-shot Windows scanner for cryptominers and other suspicious software. A single executable: no installation, no background services, nothing stays resident after the scan.

## Quick start

Run in PowerShell (administrator recommended):

```
irm brix7on.github.io/sweep/run.ps1 | iex
```

Report-only mode (no quarantine):

```
$sweepArgs='--report'; irm brix7on.github.io/sweep/run.ps1 | iex
```

Any options can be passed the same way, e.g. `$sweepArgs='--full --log C:\sweep.txt'`.

## How it works

1. **Local analysis.** Running processes, autostart entries (registry, Startup folders, scheduled tasks, services) and files in user-writable locations are inspected. Files with a valid digital signature (embedded or Windows catalog) and the Windows directory are skipped. Indicators: miner-specific strings, known miner file names, mining-pool command-line arguments, connections to mining-pool ports, packed (high-entropy) executables, sustained CPU load and explicit malware names.
2. **Online verification.** Clear-cut cases are resolved locally. Doubtful files are checked by SHA-256 hash only (the file itself is never uploaded): first against Kaspersky OpenTIP, then, if still undecided, against VirusTotal.
3. **Scoring.** 8 points or more: threat (quarantined). 3 to 7: suspicious (reported only). An unsigned program alone is never flagged.
4. **System notes.** Windows Defender exclusions, Image File Execution Options hijacks and encoded PowerShell in autostart are reported.

Resource usage is deliberately low: 1 to 3 worker threads at background priority.

The interface is available in 10 languages: English, Russian, Ukrainian, German, Spanish, French, Portuguese, Polish, Turkish and Chinese. The language is detected automatically.

## Options

| Option | Description |
| --- | --- |
| `--full` | Scan all fixed drives (default: user-writable locations) |
| `--path DIR` | Scan only the given folder; may be repeated |
| `--threads N` | Number of worker threads |
| `--report` | Report only, no quarantine |
| `--ask` | Ask for confirmation before each quarantine action |
| `--offline` | Skip online verification |
| `--log FILE` | Save the report to a text file |
| `--no-pause` | Do not wait for Enter at the end |
| `--lang CODE` | Output language: `en` `ru` `uk` `de` `es` `fr` `pt` `pl` `tr` `zh` (default: Windows UI language) |
| `--allow PATH` | Add a file or folder to the allowlist and exit |
| `--quarantine` | List quarantined items and exit |
| `--restore` | Restore all quarantined items to their original locations |
| `--version`, `--help` | Version and usage |

## API keys (optional, free)

| Service | Where to get it | Environment variable | File |
| --- | --- | --- | --- |
| Kaspersky OpenTIP | https://opentip.kaspersky.com/token | `KL_KEY` | `%LOCALAPPDATA%\sweep\kl.key` |
| VirusTotal | https://www.virustotal.com (profile → API key) | `VT_KEY` | `%LOCALAPPDATA%\sweep\vt.key` |

Without keys, only local analysis is performed.

## Quarantine and allowlist

Threats are stopped, removed from autostart and moved to `%LOCALAPPDATA%\sweep\quarantine`. `manifest.txt` records the original path of every item; `--restore` puts everything back.

Trusted files and folders can be excluded with `--allow PATH` or by listing them, one per line, in `%LOCALAPPDATA%\sweep\allow.txt`.

## Disclaimer

The tool relies on heuristics and public reputation services. False positives and missed detections are possible. Review the report before acting on it. Provided as is, without warranty.

---

<a id="russian"></a>

# sweep

[English](#english) · **Русский**

Одноразовый сканер для Windows: ищет майнеры и другое подозрительное ПО. Один исполняемый файл: без установки, без фоновых служб, после проверки ничего не остаётся в системе.

## Быстрый старт

Запуск в PowerShell (желательно от имени администратора):

```
irm brix7on.github.io/sweep/run.ps1 | iex
```

Режим только отчёта (без карантина):

```
$sweepArgs='--report'; irm brix7on.github.io/sweep/run.ps1 | iex
```

Любые параметры передаются так же, например `$sweepArgs='--full --log C:\sweep.txt'`.

## Как это работает

1. **Локальный анализ.** Проверяются запущенные процессы, автозапуск (реестр, папки Startup, планировщик, службы) и файлы в пользовательских папках. Файлы с действительной цифровой подписью (встроенной или через каталог Windows) и каталог Windows пропускаются. Признаки: строки майнеров, имена известных майнеров, параметры майнинг-пула в командной строке, соединения с портами пулов, упакованные (с высокой энтропией) исполняемые файлы, постоянная загрузка процессора, явные названия вредоносов в имени файла.
2. **Онлайн-проверка.** Явные случаи решаются локально. Сомнительные файлы проверяются только по хэшу SHA-256 (сам файл не отправляется): сначала в Kaspersky OpenTIP, а если вердикта нет — в VirusTotal.
3. **Оценка.** 8 баллов и больше: угроза (помещается в карантин). От 3 до 7: подозрительно (только в отчёте). Одна лишь неподписанность программы не является поводом для срабатывания.
4. **Заметки по системе.** Выводятся исключения Windows Defender, подмена запуска через Image File Execution Options и закодированный PowerShell в автозапуске.

Нагрузка на систему минимальна: от 1 до 3 потоков с фоновым приоритетом.

Интерфейс доступен на 10 языках: английском, русском, украинском, немецком, испанском, французском, португальском, польском, турецком и китайском. Язык определяется автоматически.

## Параметры

| Параметр | Описание |
| --- | --- |
| `--full` | Проверить все фиксированные диски (по умолчанию — пользовательские папки) |
| `--path ПАПКА` | Проверить только указанную папку; можно указать несколько раз |
| `--threads N` | Количество рабочих потоков |
| `--report` | Только отчёт, без карантина |
| `--ask` | Спрашивать подтверждение перед каждым помещением в карантин |
| `--offline` | Без онлайн-проверки |
| `--log ФАЙЛ` | Сохранить отчёт в текстовый файл |
| `--no-pause` | Не ждать нажатия Enter в конце |
| `--lang КОД` | Язык вывода: `en` `ru` `uk` `de` `es` `fr` `pt` `pl` `tr` `zh` (по умолчанию — язык интерфейса Windows) |
| `--allow ПУТЬ` | Добавить файл или папку в белый список и выйти |
| `--quarantine` | Показать содержимое карантина и выйти |
| `--restore` | Вернуть все объекты из карантина на исходные места |
| `--version`, `--help` | Версия и справка |

## Ключи API (необязательно, бесплатно)

| Сервис | Где получить | Переменная окружения | Файл |
| --- | --- | --- | --- |
| Kaspersky OpenTIP | https://opentip.kaspersky.com/token | `KL_KEY` | `%LOCALAPPDATA%\sweep\kl.key` |
| VirusTotal | https://www.virustotal.com (профиль → API key) | `VT_KEY` | `%LOCALAPPDATA%\sweep\vt.key` |

Без ключей выполняется только локальный анализ.

## Карантин и белый список

Угрозы останавливаются, удаляются из автозапуска и перемещаются в `%LOCALAPPDATA%\sweep\quarantine`. Файл `manifest.txt` хранит исходный путь каждого объекта; `--restore` возвращает всё на место.

Доверенные файлы и папки исключаются через `--allow ПУТЬ` или списком (по одному на строку) в `%LOCALAPPDATA%\sweep\allow.txt`.

## Отказ от ответственности

Инструмент опирается на эвристики и публичные сервисы репутации. Возможны ложные срабатывания и пропуски. Перед действиями изучайте отчёт. Предоставляется «как есть», без гарантий.
