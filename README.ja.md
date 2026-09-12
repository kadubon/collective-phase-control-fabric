# Collective Phase Control Fabric

1.0.0 の mutation 検証は、完了・合格ではなく、所有者の明示的な免除として扱います。
[例外の記録](docs/mutation-exception-1.0.md)を参照してください。他の公開検証と PyPI の承認は維持します。

This file intentionally remains in English so every repository and distribution artifact follows
the project's English-only documentation requirement.

Use [README.md](README.md) for installation, scope, commands, and safety boundaries.

The 1.0 development target adds [fixed-model observation control](docs/epistemic-growth-control.md)
and [checked finite workflows](docs/checked-capability-composition.md). It defines
a [maintained public API](docs/public-api.md) while retaining Beta classification.
See the [qualification matrix](docs/roadmap-to-1.0.md) for actual release status.

Offline growth planning is documented in the English
[growth guide](docs/growth-planning.md) and [reproducible comparisons](docs/examples/growth-comparison.json).

0.7.0 では、事前宣言した有限の候補集合から潜在アクションをモデル条件付きで有効化する
「Bounded Endogenous Capability Frontier Expansion」を追加しました。
`cpcf growth example --scenario frontier-chain --json` で多段連鎖を確認できます。
[仕様と制約](docs/endogenous-capability-frontier.md)を参照してください。能力の承認・実行権限・
実世界の能力再生産は別の問題です。外部の加速実験は実施していません。
