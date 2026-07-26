import { Elena, html } from "@elenajs/core";

/**
 * <i-scope-list> — checkbox list of OAuth scopes for the consent screen.
 *
 * Attributes: scopes (space-separated), required (space-separated, forced on)
 * Usage: <i-scope-list scopes="profile email offline_access" required="profile"></i-scope-list>
 */
export default class IScopeList extends Elena(HTMLElement) {
	static override tagName = "i-scope-list";
	static override props = ["scopes", "required"];

	scopes = "";
	required = "";

	private descriptions: Record<string, string> = {
		profile: "Your profile (name, photo, URL)",
		email: "Your email address",
		openid: "Authenticate with OpenID Connect (issues an id_token)",
		offline_access: "Stay signed in to this app long-term",
	};

	override render() {
		const required = this.required.split(" ").filter(Boolean);
		const items = this.scopes
			.split(" ")
			.filter(Boolean)
			.map((scope) => {
				const isRequired = required.includes(scope);
				const description = this.descriptions[scope] ?? scope;
				return html`
					<li>
						<label>
							<input
								type="checkbox"
								name="scope"
								value="${scope}"
								${isRequired ? "checked disabled" : "checked"}
							/>
							<span>
								${description}${isRequired ? html`<em class="req">(required)</em>` : ""}
							</span>
						</label>
					</li>
				`;
			});
		return html`<ul class="scope-list">${items}</ul>`;
	}
}
IScopeList.define();
