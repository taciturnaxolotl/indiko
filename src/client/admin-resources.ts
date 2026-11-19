import "./ds";
import { apiFetch } from "./api";
import { escapeHtml } from "./escape";
import { requirePage } from "./session";

interface Resource {
	id: number;
	identifier: string;
	name: string;
	description: string | null;
	logoUrl: string | null;
	availableRoles: string[] | null;
	defaultRole: string | null;
	restrictClients: boolean;
	assignmentRequired: boolean;
	clientCount?: number;
	userCount?: number;
}

interface ResourceDetail {
	resource: Resource;
	clients: {
		clientId: string;
		name: string | null;
		allowedRoles: string[] | null;
	}[];
	users: { username: string; name: string | null; role: string }[];
}

const list = document.getElementById("resourceList") as HTMLElement;
const modal = document.getElementById("resourceModal") as HTMLElement;
const toast = document.getElementById("toast") as HTMLElement & {
	show: (message: string, kind?: "success" | "error") => void;
};
const field = (id: string) => document.getElementById(id) as HTMLInputElement;

let resources: Resource[] = [];
let openId: number | null = null;
let editing: Resource | null = null;

const roleList = (value: string): string[] | null => {
	const roles = value
		.split(",")
		.map((r) => r.trim())
		.filter(Boolean);
	return roles.length > 0 ? roles : null;
};

async function send(
	url: string,
	method: string,
	body?: unknown,
): Promise<boolean> {
	const response = await apiFetch(url, {
		method,
		headers: body === undefined ? {} : { "Content-Type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
	if (response.ok) return true;
	const data = (await response.json().catch(() => ({}))) as { error?: string };
	toast.show(data.error ?? `Request failed (${response.status})`, "error");
	return false;
}

async function loadResources() {
	const response = await apiFetch("/api/admin/resources", {});
	if (!response.ok) {
		list.innerHTML = '<div class="error">Failed to load resources</div>';
		return;
	}
	resources = ((await response.json()) as { resources: Resource[] }).resources;
	render();
	if (openId !== null) await loadDetail(openId);
}

function render() {
	if (resources.length === 0) {
		list.innerHTML =
			'<div class="empty">No resources registered. Unregistered audiences still work; they just have no allowlist or roles.</div>';
		return;
	}
	list.innerHTML = resources
		.map(
			(r) => `
		<div class="resource-item">
			<button type="button" class="resource-summary" data-action="toggle" data-id="${r.id}" aria-expanded="${openId === r.id}">
				<div>
					<div class="resource-name">${escapeHtml(r.name)}</div>
					<div class="resource-identifier">${escapeHtml(r.identifier)}</div>
				</div>
				<div class="badges">
					<span class="badge ${r.restrictClients ? "badge-strong" : ""}">${r.restrictClients ? `${r.clientCount ?? 0} apps allowed` : "any app"}</span>
					${r.assignmentRequired ? '<span class="badge badge-strong">role required</span>' : ""}
					<span class="badge">${r.userCount ?? 0} assigned</span>
				</div>
			</button>
			<div class="resource-detail" id="detail-${r.id}" ${openId === r.id ? "" : "hidden"}></div>
		</div>`,
		)
		.join("");
}

function roleOptions(resource: Resource, current?: string): string {
	if (!resource.availableRoles) {
		return `<input type="text" name="role" placeholder="role" value="${escapeHtml(current ?? "")}" required>`;
	}
	return `<select name="role">${resource.availableRoles
		.map(
			(r) =>
				`<option value="${escapeHtml(r)}" ${r === current ? "selected" : ""}>${escapeHtml(r)}</option>`,
		)
		.join("")}</select>`;
}

interface Choices {
	apps: { clientId: string; name: string }[];
	people: { username: string; name: string | null }[];
}

let choices: Promise<Choices> | undefined;

/** Apps and people indiko already knows, for the pickers. Fetched once per page. */
function loadChoices(): Promise<Choices> {
	choices ??= Promise.all([
		apiFetch("/api/admin/clients", {}).then((r) =>
			r.ok ? r.json() : { clients: [] },
		),
		apiFetch("/api/users", {}).then((r) => (r.ok ? r.json() : { users: [] })),
	]).then(([apps, people]) => ({
		apps: (apps.clients ?? []) as Choices["apps"],
		people: (people.users ?? []) as Choices["people"],
	}));
	return choices;
}

/** Ceiling picker: one checkbox per defined role; free-form roles stay a text box. */
function ceilingPicker(resource: Resource): string {
	if (!resource.availableRoles) {
		return '<input type="text" name="allowedRoles" placeholder="allowed roles, comma separated (any)">';
	}
	return `<fieldset class="ceiling"><legend>allowed roles <span class="hint">(none ticked: any)</span></legend>${resource.availableRoles
		.map(
			(r) =>
				`<label><input type="checkbox" name="allowedRole" value="${escapeHtml(r)}"> ${escapeHtml(r)}</label>`,
		)
		.join("")}</fieldset>`;
}

async function loadDetail(id: number) {
	const container = document.getElementById(`detail-${id}`);
	if (!container) return;
	const response = await apiFetch(`/api/admin/resources/${id}`, {});
	if (!response.ok) {
		container.innerHTML = '<div class="error">Failed to load resource</div>';
		return;
	}
	const { resource, clients, users } =
		(await response.json()) as ResourceDetail;
	const known = await loadChoices();
	const listed = new Set(clients.map((c) => c.clientId));
	const assigned = new Set(users.map((u) => u.username));
	const appOptions = known.apps
		.filter((a) => !listed.has(a.clientId))
		.map(
			(a) =>
				`<option value="${escapeHtml(a.clientId)}">${escapeHtml(a.name)}</option>`,
		)
		.join("");
	const personOptions = known.people
		.filter((p) => !assigned.has(p.username))
		.map(
			(p) =>
				`<option value="${escapeHtml(p.username)}">${escapeHtml(p.name ?? p.username)}</option>`,
		)
		.join("");

	const clientRows = clients.length
		? clients
				.map(
					(c) => `
			<div class="row">
				<div>
					${c.name ? `<div>${escapeHtml(c.name)}</div>` : ""}
					<div class="mono">${escapeHtml(c.clientId)}</div>
				</div>
				<span class="badge">${c.allowedRoles ? escapeHtml(c.allowedRoles.join(", ")) : "any role"}</span>
				<button type="button" class="small-btn small-btn-danger" data-action="remove-client" data-id="${id}" data-client="${escapeHtml(c.clientId)}">remove</button>
			</div>`,
				)
				.join("")
		: `<div class="row-empty">${resource.restrictClients ? "No apps allowed yet, so every request for this resource is refused." : "Any app may request this resource. Listing an app here only narrows its roles."}</div>`;

	const userRows = users.length
		? users
				.map(
					(u) => `
			<form class="row set-role" data-action="set-role" data-id="${id}">
				<div>${escapeHtml(u.name ?? u.username)} <span class="mono">@${escapeHtml(u.username)}</span></div>
				<input type="hidden" name="username" value="${escapeHtml(u.username)}">
				${roleOptions(resource, u.role)}
				<button type="submit" class="small-btn">save</button>
				<button type="button" class="small-btn small-btn-danger" data-action="remove-user" data-id="${id}" data-user="${escapeHtml(u.username)}">remove</button>
			</form>`,
				)
				.join("")
		: `<div class="row-empty">${resource.defaultRole ? `Everyone gets the default role, ${escapeHtml(resource.defaultRole)}.` : "Nobody holds a role here yet."}</div>`;

	container.innerHTML = `
		${resource.description ? `<p class="detail-help">${escapeHtml(resource.description)}</p>` : ""}
		<section class="detail-section">
			<h4>allowed apps</h4>
			<p class="detail-help">Which client ids may request this audience. Allowed roles cap what a token from that app carries, even for an admin.</p>
			<div class="row-list">${clientRows}</div>
			<form class="add-row add-client" data-action="add-client" data-id="${id}">
				<input type="text" name="clientId" list="apps-${id}" placeholder="pick an app, or paste a client URL not seen yet" required autocomplete="off">
				<datalist id="apps-${id}">${appOptions}</datalist>
				<button type="submit" class="small-btn">allow</button>
				${ceilingPicker(resource)}
			</form>
		</section>
		<section class="detail-section">
			<h4>people</h4>
			<p class="detail-help">Introspection reports this role for tokens bound to the resource. Changes apply to live tokens immediately.</p>
			<div class="row-list">${userRows}</div>
			<form class="add-row" data-action="add-user" data-id="${id}">
				<input type="text" name="username" list="people-${id}" placeholder="pick a person" required autocomplete="off">
				<datalist id="people-${id}">${personOptions}</datalist>
				${roleOptions(resource)}
				<button type="submit" class="small-btn">assign</button>
			</form>
		</section>
		<div class="detail-actions">
			<button type="button" class="small-btn" data-action="edit" data-id="${id}">edit settings</button>
			<button type="button" class="small-btn small-btn-danger" data-action="delete" data-id="${id}">delete</button>
		</div>`;
}

function openModal(resource: Resource | null) {
	editing = resource;
	(document.getElementById("resourceModalTitle") as HTMLElement).textContent =
		resource ? "edit resource" : "register resource";
	field("resIdentifier").value = resource?.identifier ?? "";
	field("resIdentifier").disabled = resource !== null;
	field("resName").value = resource?.name ?? "";
	(document.getElementById("resDescription") as HTMLTextAreaElement).value =
		resource?.description ?? "";
	field("resLogo").value = resource?.logoUrl ?? "";
	field("resRoles").value = resource?.availableRoles?.join(", ") ?? "";
	field("resDefaultRole").value = resource?.defaultRole ?? "";
	field("resRestrict").checked = resource?.restrictClients ?? true;
	field("resAssignment").checked = resource?.assignmentRequired ?? false;
	modal.style.display = "flex";
}

async function submitModal() {
	const body = {
		...(editing ? {} : { identifier: field("resIdentifier").value.trim() }),
		name: field("resName").value.trim(),
		description:
			(
				document.getElementById("resDescription") as HTMLTextAreaElement
			).value.trim() || null,
		logoUrl: field("resLogo").value.trim() || null,
		availableRoles: roleList(field("resRoles").value),
		defaultRole: field("resDefaultRole").value.trim() || null,
		restrictClients: field("resRestrict").checked,
		assignmentRequired: field("resAssignment").checked,
	};
	const ok = editing
		? await send(`/api/admin/resources/${editing.id}`, "PUT", body)
		: await send("/api/admin/resources", "POST", body);
	if (!ok) return;
	modal.style.display = "none";
	toast.show(editing ? "Resource updated" : "Resource registered");
	await loadResources();
}

document.addEventListener("click", async (event) => {
	const target = (event.target as HTMLElement).closest<HTMLElement>(
		"[data-action]",
	);
	if (!target || target.tagName === "FORM") return;
	const id = Number(target.dataset.id);

	switch (target.dataset.action) {
		case "toggle": {
			openId = openId === id ? null : id;
			render();
			if (openId !== null) await loadDetail(openId);
			break;
		}
		case "close-modal":
			modal.style.display = "none";
			break;
		case "edit":
			openModal(resources.find((r) => r.id === id) ?? null);
			break;
		case "delete": {
			const resource = resources.find((r) => r.id === id);
			if (
				!resource ||
				!confirm(
					`Delete ${resource.name}? Every outstanding token for ${resource.identifier} is revoked.`,
				)
			)
				return;
			if (await send(`/api/admin/resources/${id}`, "DELETE")) {
				openId = null;
				toast.show("Resource deleted");
				await loadResources();
			}
			break;
		}
		case "remove-client": {
			const clientId = target.dataset.client ?? "";
			if (
				await send(
					`/api/admin/resources/${id}/clients?client_id=${encodeURIComponent(clientId)}`,
					"DELETE",
				)
			)
				await loadResources();
			break;
		}
		case "remove-user": {
			const username = target.dataset.user ?? "";
			if (
				await send(
					`/api/admin/resources/${id}/users/${encodeURIComponent(username)}`,
					"DELETE",
				)
			)
				await loadResources();
			break;
		}
	}
});

document.addEventListener("submit", async (event) => {
	const form = event.target as HTMLFormElement;
	if (!form.dataset.action) return;
	event.preventDefault();
	const id = Number(form.dataset.id);
	const data = new FormData(form);

	if (form.dataset.action === "add-client") {
		const ok = await send(`/api/admin/resources/${id}/clients`, "PUT", {
			clientId: String(data.get("clientId") ?? "").trim(),
			allowedRoles: data.has("allowedRole")
				? data.getAll("allowedRole").map(String)
				: roleList(String(data.get("allowedRoles") ?? "")),
		});
		if (ok) await loadResources();
	} else if (["add-user", "set-role"].includes(form.dataset.action)) {
		const username = String(data.get("username") ?? "").trim();
		const ok = await send(
			`/api/admin/resources/${id}/users/${encodeURIComponent(username)}`,
			"PUT",
			{ role: String(data.get("role") ?? "").trim() },
		);
		if (ok) await loadResources();
	}
});

(
	document.getElementById("createResourceBtn") as HTMLButtonElement
).addEventListener("click", () => openModal(null));
(document.getElementById("resSubmit") as HTMLButtonElement).addEventListener(
	"click",
	submitModal,
);

void requirePage({ admin: true });
loadResources().catch((error) => {
	console.error("Auth check failed:", error);
	list.innerHTML = '<div class="error">Failed to load resources</div>';
});
