# わが家のこよみ

パパ・ママ・ゆづの家族カレンダー。

- 画面：このリポジトリを GitHub Pages で公開（`index.html`、通知用の `sw.js`、ホーム画面用の `manifest.webmanifest`）
- データ：Supabase プロジェクト「わが家のこよみ」（東京）。テーブルは直接アクセス不可で、`supabase/functions/koyomi-api` を通してのみ読み書きします
- ログイン：家族の合言葉。合言葉そのものは保存しておらず、照合用のハッシュだけを持っています
- 毎朝 6:30 に今日の予定・締め切り・ゴミの日を通知（Supabase の pg_cron）
