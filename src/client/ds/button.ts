import { Elena } from "@elenajs/core";

/**
 * <i-button> — brutalist action button. Composite: put a native <button>
 * inside it; the component only supplies the styling and forwards the
 * disabled attribute down.
 *
 * Usage: <i-button variant="ghost"><button type="submit">Save</button></i-button>
 */
export default class IButton extends Elena(HTMLElement) {
	static override tagName = "i-button";
	static override props = ["variant", "size", "disabled"];

	variant = "primary";
	size = "md";
	disabled = false;

	override updated() {
		const btn = this.querySelector("button");
		if (btn) btn.disabled = this.disabled;
	}
}
IButton.define();
