import { defineCollection, z } from "astro:content";

const postsCollection = defineCollection({
	schema: z.object({
		title: z.string(),
		published: z.date(),
		updated: z.date().optional(),
		draft: z.boolean().optional().default(false),
		description: z.string().optional().default(""),
		image: z.string().optional().default(""),
		tags: z.array(z.string()).optional().default([]),
		category: z.string().optional().nullable().default(""),
		lang: z.string().optional().default(""),
		/**
		 * File name (without `.md`) of the post this entry translates. Set this only
		 * on the translated version: the original stays untouched and both directions
		 * are resolved from it. Matched against the file name rather than `slug`,
		 * because Astro's slug lowercases and strips punctuation. Translated entries
		 * are kept out of listings, archives, tag and category counts and the RSS
		 * feed, so a report is never counted twice.
		 */
		translationOf: z.string().optional(),

		/* For internal use */
		prevTitle: z.string().default(""),
		prevSlug: z.string().default(""),
		nextTitle: z.string().default(""),
		nextSlug: z.string().default(""),
	}),
});
const specCollection = defineCollection({
	schema: z.object({}),
});
export const collections = {
	posts: postsCollection,
	spec: specCollection,
};
