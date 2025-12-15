declare module "bun" {
	interface Env {
		ORIGIN: string;
		RP_ID: string;
		NODE_ENV?: "dev" | "production";
		PORT?: string;
	}
}
