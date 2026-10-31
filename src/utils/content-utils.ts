import { type CollectionEntry, getCollection } from "astro:content";
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import { getCategoryUrl } from "@utils/url-utils.ts";

/**
 * A post carrying `translationOf` is an alternate language version of another post.
 * Translations get their own route but must stay out of listings, archives, tag and
 * category counts and the RSS feed, otherwise every report is listed twice.
 */
export function isTranslation(entry: CollectionEntry<"posts">) {
	return !!entry.data.translationOf;
}

/**
 * The file name without its extension, preserving case and punctuation that
 * Astro's slug generation strips (`VNS-Stealer` → `vns-stealer`, `stage2.dll`
 * → `stage2dll`). `translationOf` stores the name as written, so pairs must be
 * matched on this rather than on `slug`.
 */
export function getPostFileStem(entry: CollectionEntry<"posts">) {
	const p = (entry as { filePath?: string }).filePath ?? entry.id;
	return p.split(/[\\/]/).pop()?.replace(/\.mdx?$/i, "") ?? entry.slug;
}

// // Retrieve posts and sort them by publication date
async function getRawSortedPosts(includeTranslations = false) {
	const allBlogPosts = await getCollection("posts", ({ data }) => {
		return import.meta.env.PROD ? data.draft !== true : true;
	});

	const visible = includeTranslations
		? allBlogPosts
		: allBlogPosts.filter((entry) => !isTranslation(entry));

	const sorted = visible.sort(
		(a: CollectionEntry<"posts">, b: CollectionEntry<"posts">) => {
			const dateA = new Date(a.data.published);
			const dateB = new Date(b.data.published);
			return dateA > dateB ? -1 : 1;
		},
	);
	return sorted;
}

/** Every publishable post, translations included. Used for route generation. */
export async function getAllSortedPosts() {
	return getRawSortedPosts(true);
}

export async function getSortedPosts() {
	const sorted = await getRawSortedPosts();

	for (let i = 1; i < sorted.length; i++) {
		sorted[i].data.nextSlug = sorted[i - 1].slug;
		sorted[i].data.nextTitle = sorted[i - 1].data.title;
	}
	for (let i = 0; i < sorted.length - 1; i++) {
		sorted[i].data.prevSlug = sorted[i + 1].slug;
		sorted[i].data.prevTitle = sorted[i + 1].data.title;
	}

	return sorted;
}
export type PostForList = {
	slug: string;
	data: CollectionEntry<"posts">["data"];
};
export async function getSortedPostsList(): Promise<PostForList[]> {
	const sortedFullPosts = await getRawSortedPosts();

	// delete post.body
	const sortedPostsList = sortedFullPosts.map((post) => ({
		slug: post.slug,
		data: post.data,
	}));

	return sortedPostsList;
}
export type Tag = {
	name: string;
	count: number;
};

export async function getTagList(): Promise<Tag[]> {
	const allBlogPosts = await getCollection<"posts">("posts", ({ data }) => {
		return import.meta.env.PROD ? data.draft !== true : true;
	});
	const listedPosts = allBlogPosts.filter((entry) => !isTranslation(entry));

	const countMap: { [key: string]: number } = {};
	listedPosts.forEach((post: { data: { tags: string[] } }) => {
		post.data.tags.forEach((tag: string) => {
			if (!countMap[tag]) countMap[tag] = 0;
			countMap[tag]++;
		});
	});

	// sort tags
	const keys: string[] = Object.keys(countMap).sort((a, b) => {
		return a.toLowerCase().localeCompare(b.toLowerCase());
	});

	return keys.map((key) => ({ name: key, count: countMap[key] }));
}

export type Category = {
	name: string;
	count: number;
	url: string;
};

export async function getCategoryList(): Promise<Category[]> {
	const allBlogPosts = await getCollection<"posts">("posts", ({ data }) => {
		return import.meta.env.PROD ? data.draft !== true : true;
	});
	const listedPosts = allBlogPosts.filter((entry) => !isTranslation(entry));
	const count: { [key: string]: number } = {};
	listedPosts.forEach((post: { data: { category: string | null } }) => {
		if (!post.data.category) {
			const ucKey = i18n(I18nKey.uncategorized);
			count[ucKey] = count[ucKey] ? count[ucKey] + 1 : 1;
			return;
		}

		const categoryName =
			typeof post.data.category === "string"
				? post.data.category.trim()
				: String(post.data.category).trim();

		count[categoryName] = count[categoryName] ? count[categoryName] + 1 : 1;
	});

	const lst = Object.keys(count).sort((a, b) => {
		return a.toLowerCase().localeCompare(b.toLowerCase());
	});

	const ret: Category[] = [];
	for (const c of lst) {
		ret.push({
			name: c,
			count: count[c],
			url: getCategoryUrl(c),
		});
	}
	return ret;
}
