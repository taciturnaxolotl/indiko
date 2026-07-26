import { Elena } from "@elenajs/core";

/**
 * <i-card> — quiet surface. Composite: wraps and styles the content
 * composed inside it, does NOT replace it.
 *
 * Usage:
 *   <i-card>
 *     <h2 class="card-title">passkeys</h2>
 *     …content stays intact…
 *   </i-card>
 */
export default class ICard extends Elena(HTMLElement) {
	static override tagName = "i-card";
	// No render(): composite component, content is preserved.
}
ICard.define();
