import { Elena, html } from "@elenajs/core";

/**
 * <i-passkey-row> — one passkey with rename/delete actions.
 *
 * Attributes: pid, name, created (unix seconds)
 * Emits: "rename" {id, name}, "remove" {id}
 */
export default class IPasskeyRow extends Elena(HTMLElement) {
	static override tagName = "i-passkey-row";
	static override props = ["pid", "name", "created"];

	pid = "";
	name = "";
	created = "";

	private editing = false;

	private date(): string {
		const ts = Number(this.created);
		if (!ts) return "";
		return new Date(ts * 1000).toLocaleDateString(undefined, {
			year: "numeric",
			month: "short",
			day: "numeric",
		});
	}

	override render() {
		if (this.editing) {
			return html`
				<div class="row">
					<input class="rename-input" value="${this.name}" />
					<div class="actions">
						<button data-act="save" class="mini">save</button>
						<button data-act="cancel" class="mini ghost">cancel</button>
					</div>
				</div>
			`;
		}
		return html`
			<div class="row">
				<div class="info">
					<div class="name">${this.name}</div>
					<div class="date">added ${this.date()}</div>
				</div>
				<div class="actions">
					<button data-act="edit" class="mini">rename</button>
					<button data-act="delete" class="mini danger">delete</button>
				</div>
			</div>
		`;
	}

	override firstUpdated() {
		this.addEventListener("click", this.onClick);
	}

	private onClick = (e: Event) => {
		const btn = (e.target as HTMLElement).closest("button");
		if (!btn) return;
		const act = (btn as HTMLButtonElement).dataset.act;

		if (act === "edit") {
			this.editing = true;
			this.requestUpdate();
		} else if (act === "cancel") {
			this.editing = false;
			this.requestUpdate();
		} else if (act === "save") {
			const input = this.querySelector<HTMLInputElement>(".rename-input");
			const name = input?.value.trim() ?? "";
			this.editing = false;
			this.dispatchEvent(
				new CustomEvent("rename", {
					detail: { id: this.pid, name },
					bubbles: true,
				}),
			);
			if (name) this.name = name;
			this.requestUpdate();
		} else if (act === "delete") {
			this.dispatchEvent(
				new CustomEvent("remove", {
					detail: { id: this.pid },
					bubbles: true,
				}),
			);
		}
	};
}
IPasskeyRow.define();
