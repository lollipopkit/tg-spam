package events

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	tbapi "github.com/OvyFlash/telegram-bot-api"

	"github.com/umputun/tg-spam/app/bot"
)

// captchaReleasePrefix marks callback data of the unban buttons on captcha notices in the admin chat:
// "U?<userID>" asks to confirm, "U<userID>" lets the member in, "U.<userID>" is a button already used
const captchaReleasePrefix = "U"

const (
	captchaReportInterval = 3 * time.Second // telegram allows a group about 20 messages a minute
	captchaReportBatch    = 20              // members per notice, one button each
	captchaReportQueue    = 500             // members queued past this are counted, not listed
	captchaReportLimit    = 4000            // notice length in UTF-16 units, under telegram's 4096
	captchaReportAttempts = 3               // sends of a notice before its members are given up
)

type captchaReport struct {
	user          bot.User
	action, cause string
	attempts      int // failed sends of a notice listing the member
}

// captchaReports posts the captcha's bans and mutes to the admin chat. Add only queues, so the timers,
// workers and update loop calling it never wait for telegram; Run posts the queue in batches, at most one
// notice per interval, so a join raid neither runs into telegram's rate limit nor floods the chat
type captchaReports struct {
	tbAPI    TbAPI
	chatID   int64
	interval time.Duration

	mu      sync.Mutex
	queue   []captchaReport
	dropped int // members past captchaReportQueue since the last notice
}

// Add queues a notice: action is "banned" or "muted", cause the duration and the reason
func (r *captchaReports) Add(user bot.User, action, cause string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) >= captchaReportQueue {
		r.dropped++
		return
	}
	r.queue = append(r.queue, captchaReport{user: user, action: action, cause: cause})
}

// Run posts queued notices until ctx is done, then posts what is left without waiting for the interval
func (r *captchaReports) Run(ctx context.Context) {
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// bounded, as failed sends are queued again; telegram may refuse some under its rate limit
			for range captchaReportQueue/captchaReportBatch + 1 {
				if !r.flush() {
					return
				}
			}
			return
		case <-tick.C:
			r.flush()
		}
	}
}

// flush posts the next notice: one line and one unban button per member, up to captchaReportBatch members
// and captchaReportLimit long. members of a notice telegram refuses are queued again, up to
// captchaReportAttempts sends. it reports whether anything is left to post
func (r *captchaReports) flush() bool {
	r.mu.Lock()
	var batch []captchaReport
	var lines []string
	size := 0
	for _, rep := range r.queue {
		line := fmt.Sprintf("%s [%s](tg://user?id=%d) %s", rep.action, markdownV1LinkLabel(rep.user.String()),
			rep.user.ID, escapeMarkDownV1Text(rep.cause))
		lineSize := len(utf16.Encode([]rune(line))) + 1
		if len(batch) == captchaReportBatch || len(batch) > 0 && size+lineSize > captchaReportLimit {
			break
		}
		batch, lines, size = append(batch, rep), append(lines, line), size+lineSize
	}
	r.queue = slices.Delete(r.queue, 0, len(batch))
	dropped := r.dropped
	r.dropped = 0
	r.mu.Unlock()
	if len(batch) == 0 && dropped == 0 {
		return false
	}

	rows := make([][]tbapi.InlineKeyboardButton, 0, len(batch))
	for _, rep := range batch {
		rows = append(rows, tbapi.NewInlineKeyboardRow(tbapi.NewInlineKeyboardButtonData(
			releaseLabel+memberLabel(rep.user), fmt.Sprintf("%s?%d", captchaReleasePrefix, rep.user.ID))))
	}
	if dropped > 0 {
		lines = append(lines, fmt.Sprintf("%d more banned or muted by the captcha, not listed", dropped))
	}
	msg := tbapi.NewMessage(r.chatID, strings.Join(lines, "\n"))
	msg.ParseMode = tbapi.ModeMarkdown
	msg.LinkPreviewOptions = tbapi.LinkPreviewOptions{IsDisabled: true}
	if len(rows) > 0 {
		msg.ReplyMarkup = tbapi.NewInlineKeyboardMarkup(rows...)
	}
	_, err := r.tbAPI.Send(msg)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		retry := make([]captchaReport, 0, len(batch))
		for _, rep := range batch {
			rep.attempts++
			if rep.attempts < captchaReportAttempts {
				retry = append(retry, rep)
			}
		}
		r.queue = append(retry, r.queue...)
		r.dropped += dropped
		log.Printf("[WARN] failed to send captcha notice for %d members, %d given up: %v", len(batch),
			len(batch)-len(retry), err)
	}
	return len(r.queue) > 0 || r.dropped > 0
}

// labels of the unban button through its states; the member's name follows
const (
	releaseLabel  = "unban "
	confirmLabel  = "confirm unban "
	releasedLabel = "✓ unbanned "
)

// memberLabel names the member on a button: @username, the display name or the ID
func memberLabel(user bot.User) string {
	switch {
	case user.Username != "":
		return "@" + user.Username
	case user.DisplayName != "":
		return truncateString(user.DisplayName, 32, "…")
	default:
		return strconv.FormatInt(user.ID, 10)
	}
}

// procCaptchaRelease handles the unban buttons on captcha notices. the first press turns the button into a
// confirmation, the second lets the member in (releaseMember) and approves them, so a later join brings no
// captcha. the button stays, marked with who pressed it, keeping the notice's links intact
func (l *TelegramListener) procCaptchaRelease(query *tbapi.CallbackQuery) {
	if query.Message == nil || query.Message.Chat.ID != l.adminChatID || query.Message.ReplyMarkup == nil {
		answerCallback(l.TbAPI, query.ID, "")
		return
	}
	if l.Dry || l.TrainingMode {
		answerCallback(l.TbAPI, query.ID, "nothing changed in dry and training modes")
		return
	}
	data := strings.TrimPrefix(query.Data, captchaReleasePrefix)
	if strings.HasPrefix(data, ".") {
		answerCallback(l.TbAPI, query.ID, "already done")
		return
	}
	confirmed := !strings.HasPrefix(data, "?")
	userID, err := strconv.ParseInt(strings.TrimPrefix(data, "?"), 10, 64)
	if err != nil {
		answerCallback(l.TbAPI, query.ID, "")
		log.Printf("[WARN] invalid captcha release callback %q", query.Data)
		return
	}
	markup := *query.Message.ReplyMarkup
	button := findButton(markup, query.Data)
	if button == nil {
		answerCallback(l.TbAPI, query.ID, "")
		return
	}
	if !confirmed {
		name := strings.TrimPrefix(button.Text, releaseLabel)
		*button = tbapi.NewInlineKeyboardButtonData(confirmLabel+name, fmt.Sprintf("%s%d", captchaReleasePrefix, userID))
		l.editReleaseMarkup(query, markup)
		answerCallback(l.TbAPI, query.ID, "")
		return
	}

	name := strings.TrimPrefix(button.Text, confirmLabel)
	if err := releaseMember(l.TbAPI, l.chatID, userID); err != nil {
		answerCallback(l.TbAPI, query.ID, "failed, see the log")
		log.Printf("[WARN] failed to unban %s (%d) after captcha: %v", name, userID, err)
		return
	}
	// after the release: a refused one must leave a pending captcha to its timeout
	if l.captcha != nil {
		l.captcha.Forget(userID)
	}
	if err := l.Bot.AddApprovedUser(userID, name); err != nil {
		log.Printf("[WARN] failed to approve %s (%d) after captcha unban: %v", name, userID, err)
	}
	admin := ""
	if query.From != nil {
		admin = " by " + memberLabel(bot.User{ID: query.From.ID, Username: query.From.UserName,
			DisplayName: strings.TrimSpace(query.From.FirstName + " " + query.From.LastName)})
	}
	*button = tbapi.NewInlineKeyboardButtonData(releasedLabel+name+admin, fmt.Sprintf("%s.%d", captchaReleasePrefix, userID))
	l.editReleaseMarkup(query, markup)
	answerCallback(l.TbAPI, query.ID, "unbanned")
	log.Printf("[INFO] %s (%d) unbanned and approved after captcha%s", name, userID, admin)
}

// findButton returns the button of markup with the callback data, nil if there is none
func findButton(markup tbapi.InlineKeyboardMarkup, data string) *tbapi.InlineKeyboardButton {
	for i := range markup.InlineKeyboard {
		for j := range markup.InlineKeyboard[i] {
			if b := &markup.InlineKeyboard[i][j]; b.CallbackData != nil && *b.CallbackData == data {
				return b
			}
		}
	}
	return nil
}

func (l *TelegramListener) editReleaseMarkup(query *tbapi.CallbackQuery, markup tbapi.InlineKeyboardMarkup) {
	edit := tbapi.NewEditMessageReplyMarkup(query.Message.Chat.ID, query.Message.MessageID, markup)
	if _, err := l.TbAPI.Request(edit); err != nil {
		log.Printf("[WARN] failed to update captcha notice buttons: %v", err)
	}
}

// releaseMember lifts what the captcha put on a member: a ban is removed, keeping a member who is not banned in
// the chat, and a restriction lifted. with the status unknown both are sent, and it fails only if both do
func releaseMember(tbAPI TbAPI, chatID, userID int64) error {
	unban := func() error {
		return requestOK(tbAPI, tbapi.UnbanChatMemberConfig{OnlyIfBanned: true,
			ChatMemberConfig: tbapi.ChatMemberConfig{ChatConfig: tbapi.ChatConfig{ChatID: chatID}, UserID: userID}})
	}
	status, err := chatMemberStatus(tbAPI, chatID, userID)
	switch {
	case err != nil:
		log.Printf("[WARN] can't get member status of %d, unbanning and lifting restrictions: %v", userID, err)
		errUnban, errLift := unban(), liftRestrictions(tbAPI, chatID, userID)
		if errUnban != nil && errLift != nil {
			return fmt.Errorf("unban: %w, lift restrictions: %w", errUnban, errLift)
		}
		return nil
	case status == "kicked":
		return unban()
	case status == "restricted":
		return liftRestrictions(tbAPI, chatID, userID)
	default:
		return nil // the ban or mute has ended already
	}
}
