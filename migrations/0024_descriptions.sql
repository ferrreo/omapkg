-- Keep requester wording as an untrusted intake hint for history and review.
ALTER TABLE requests ADD COLUMN description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 500);

-- New factory revisions carry a concise verified description. NULL preserves
-- historical revisions and their original manifest hash.
ALTER TABLE revisions ADD COLUMN description TEXT CHECK(description IS NULL OR (length(description) BETWEEN 1 AND 160));
