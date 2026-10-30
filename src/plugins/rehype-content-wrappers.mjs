import { visit } from "unist-util-visit";

/**
 * Wraps wide content in scroll containers so it cannot blow out the article column.
 *
 * - `<table>` → `<div class="content-scroll table-scroll">`
 * - inline `<svg>` (the generated attack-chain diagrams, 720px wide)
 *   → `<div class="content-scroll svg-scroll">`
 *
 * Tables arrive as hast elements (markdown syntax), while inline HTML such as the
 * diagrams arrives as `raw` nodes, so each needs its own pass.
 *
 * Styling lives in `src/styles/markdown.css`.
 */
export function rehypeContentWrappers() {
	return (tree) => {
		visit(tree, "element", (node, index, parent) => {
			if (index === null || index === undefined || !parent) return;
			if (node.tagName !== "table") return;

			// Don't wrap twice if this ever runs over already-processed output.
			const className = parent.properties?.className;
			if (Array.isArray(className) && className.includes("content-scroll"))
				return;

			parent.children[index] = {
				type: "element",
				tagName: "div",
				properties: { className: ["content-scroll", "table-scroll"] },
				children: [node],
			};

			// Continue after the wrapper rather than descending into the node we moved.
			return index + 1;
		});

		visit(tree, "raw", (node, index, parent) => {
			if (index === null || index === undefined || !parent) return;
			if (!/^\s*<svg[\s>]/i.test(node.value ?? "")) return;

			parent.children[index] = {
				type: "element",
				tagName: "div",
				properties: { className: ["content-scroll", "svg-scroll"] },
				children: [{ type: "raw", value: node.value }],
			};

			return index + 1;
		});
	};
}
