---
worth: later
where: app/events/listener.go (procEvents intake guard)
added: 2026-10-30
---
# --meta.giveaway may never see a non-forwarded giveaway

The intake guard admits text-less documents, contacts and audio only when their meta check is on
(`AdmitDocuments`, `AdmitContacts`, `AdmitAudio`). `WithGiveaway` has no such entry. If a giveaway
posted directly in the group carries no text, `procEvents` drops it before `Bot.OnMessage` and
`GiveawayCheck` never fires; forwarded giveaways pass through `WithForward`.

Not confirmed: it depends on whether a non-forwarded giveaway message arrives with text. Check a real
update first, then add an `AdmitGiveaway` gate wired from `settings.Meta.Giveaway` the same way.

Carried over from the contact/audio intake item, which is fixed.
