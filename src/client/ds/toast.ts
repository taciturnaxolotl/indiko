import { Elena, html } from "@elenajs/core";

const DURATION = 6000; // ms a toast stays visible
const REMAINING_ON_HOVER = 2000; // min time left when you hover away

/**
 * <i-toast> — fixed bottom-right notification with a countdown progress bar.
 *
 * Method: show(message, kind)
 * Usage: <i-toast></i-toast>, then el.show("saved", "success")
 * Dismisses after a delay; hovering pauses the countdown and the bar.
 */
export default class IToast extends Elena(HTMLElement) {
	static override tagName = "i-toast";
	static override props = ["kind", "open", "message"];

	kind: "success" | "error" = "success";
	open = false;
	message = "";

	private timer: number | undefined;
	private shownAt = 0;
	private remaining = DURATION;
	private duration = DURATION;

	show(message: string, kind: "success" | "error" = "success") {
		this.message = message;
		this.kind = kind;
		this.open = true;
		this.startCountdown(DURATION);
	}

	private startCountdown(ms: number) {
		window.clearTimeout(this.timer);
		this.remaining = ms;
		this.duration = ms;
		this.shownAt = Date.now();
		this.timer = window.setTimeout(() => {
			this.open = false;
		}, ms);
		this.startBar();
	}

	private startBar() {
		const bar = this.querySelector<HTMLElement>(".bar");
		if (!bar) return;
		// Restart the CSS animation for the current remaining time
		bar.style.animation = "none";
		// Force reflow so the animation restarts
		void bar.offsetWidth;
		bar.style.animation = `toast-countdown ${this.remaining}ms linear forwards`;
	}

	private pauseCountdown() {
		window.clearTimeout(this.timer);
		this.remaining = Math.max(
			this.remaining - (Date.now() - this.shownAt),
			REMAINING_ON_HOVER,
		);
		const bar = this.querySelector<HTMLElement>(".bar");
		if (bar) bar.style.animationPlayState = "paused";
	}

	private resumeCountdown() {
		if (!this.open) return;
		const bar = this.querySelector<HTMLElement>(".bar");
		if (bar) bar.style.animationPlayState = "running";
		this.startCountdown(this.remaining);
	}

	override firstUpdated() {
		this.addEventListener("mouseenter", () => this.pauseCountdown());
		this.addEventListener("mouseleave", () => this.resumeCountdown());
	}

	override render() {
		return this.open
			? html`<div class="toast ${this.kind}" role="status">
					<span class="msg">${this.message}</span>
					<span class="bar"></span>
				</div>`
			: html`<div class="toast" hidden></div>`;
	}
}
IToast.define();
