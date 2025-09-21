import type { CliOptions } from "../types.js";

/**
 * A simple logger that respects the quiet flag
 * @param cliOptions - The CLI options
 * @param message - The message to log
 */
export const logger = (cliOptions: CliOptions, message: string) => {
	if (!cliOptions.quiet) {
		console.log(message);
	}
};
