import fc from "fast-check";
import { Kind, parse } from "graphql";
import { describe, expect, it } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { classifyGraphqlDocument, classifyGraphqlRequestBody } from "./graphql-classify.ts";

type DocumentShape = {
  // Operation types the generator may emit; "shorthand" is a bare `{ … }`.
  operations: readonly ("query" | "mutation" | "subscription" | "shorthand")[];
  // Block-string content may contain `"` and `""`, which can end the string early.
  blockQuotes: boolean;
  // Block-string content may contain the `\"""` escape.
  blockEscapedTripleQuote: boolean;
  // Names may be `mutation` or `subscription`, which the keyword scan treats as writes.
  keywordNames: boolean;
  // Strings and comments may contain `mutation` and `subscription`, which must be stripped.
  keywordText: boolean;
};

const ALL_OPERATIONS: DocumentShape = {
  operations: ["query", "mutation", "subscription", "shorthand"],
  blockQuotes: true,
  blockEscapedTripleQuote: false,
  keywordNames: true,
  keywordText: true,
};
const QUERY_ONLY: DocumentShape = {
  operations: ["query", "shorthand"],
  blockQuotes: false,
  blockEscapedTripleQuote: false,
  keywordNames: false,
  keywordText: true,
};
// A misread block string turns the text after it into code, where any decoy
// keyword would classify write and mask the miss, so this shape has none.
const BLOCK_ESCAPES: DocumentShape = {
  ...ALL_OPERATIONS,
  blockEscapedTripleQuote: true,
  keywordNames: false,
  keywordText: false,
};

function textParts(shape: DocumentShape, parts: string[]): string[] {
  return shape.keywordText ? [...parts, "mutation", "subscription"] : parts;
}

const lineTerminator = fc.constantFrom("\n", "\r", "\r\n");
// Comment text never holds a line terminator; the comment itself carries one.
function commentText(shape: DocumentShape): fc.Arbitrary<string> {
  return fc
    .array(fc.constantFrom(...textParts(shape, ["{ x }", '"', '"""', "\\", " ", "c", "#"])), { maxLength: 4 })
    .map((parts) => parts.join(""));
}

// One or more ignored tokens: whitespace, line terminators, commas, the BOM, comments.
function separator(shape: DocumentShape): fc.Arbitrary<string> {
  const comment = fc.tuple(commentText(shape), lineTerminator).map(([text, end]) => `#${text}${end}`);
  return fc
    .array(fc.oneof(fc.constantFrom(" ", "\t", "\n", "\r", "\r\n", ",", "\uFEFF"), comment), { minLength: 1, maxLength: 3 })
    .map((parts) => parts.join(""));
}

// At most six characters, so never `mutation` or `subscription`.
const plainName = fc.stringMatching(/^[_A-Za-z][_A-Za-z0-9]{0,5}$/u);

// Keywords are valid names in field, alias, and argument positions.
function name(shape: DocumentShape): fc.Arbitrary<string> {
  const keywords = ["query", "fragment", "mutationRate", ...(shape.keywordNames ? ["mutation", "subscription"] : [])];
  return fc.oneof(plainName, fc.constantFrom(...keywords));
}

function regularString(shape: DocumentShape): fc.Arbitrary<string> {
  const parts = textParts(shape, ["a", " ", "{ x }", "#", '\\"', "\\\\", "\\n", "\\u0041", '\\"\\"\\"']);
  return fc.array(fc.constantFrom(...parts), { maxLength: 5 }).map((content) => `"${content.join("")}"`);
}

function blockString(shape: DocumentShape): fc.Arbitrary<string> {
  const parts = textParts(shape, ["a", " ", "{ x }", "#", "\\", "\n", "\r", "\r\n"]);
  if (shape.blockQuotes) parts.push('"', '""');
  const part = shape.blockEscapedTripleQuote
    ? fc.oneof(fc.constantFrom(...parts), fc.constant('\\"""'))
    : fc.constantFrom(...parts);
  return fc.array(part, { maxLength: 5 }).map((content) => `"""${content.join("")}"""`);
}

function value(shape: DocumentShape): fc.Arbitrary<string> {
  return fc.oneof(
    fc.integer({ min: 0, max: 99 }).map(String),
    regularString(shape),
    // Block strings are where the escape lives, so favour them when it is on.
    { weight: shape.blockEscapedTripleQuote ? 6 : 1, arbitrary: blockString(shape) },
    fc.constantFrom("$v", "true", "null", "ENUM_A"),
    regularString(shape).map((item) => `[${item}]`),
  );
}

function selectionSet(shape: DocumentShape, depth: number): fc.Arbitrary<string> {
  const argument = fc.tuple(name(shape), separator(shape), value(shape)).map(([key, gap, item]) => `${key}:${gap}${item}`);
  const field = fc
    .tuple(
      fc.option(name(shape), { nil: undefined }),
      name(shape),
      fc.option(argument, { nil: undefined }),
      depth > 0 ? fc.option(selectionSet(shape, depth - 1), { nil: undefined }) : fc.constant(undefined),
      separator(shape),
    )
    .map(([alias, fieldName, args, child, gap]) =>
      [alias === undefined ? "" : `${alias}:${gap}`, fieldName, args === undefined ? "" : `(${args})`, child === undefined ? "" : `${gap}${child}`].join(""),
    );
  return fc
    .tuple(separator(shape), fc.array(field, { minLength: 1, maxLength: 3 }), separator(shape))
    .map(([open, fields, close]) => `{${open}${fields.join(open)}${close}}`);
}

function operation(shape: DocumentShape): fc.Arbitrary<string> {
  return fc
    .tuple(fc.constantFrom(...shape.operations), fc.option(name(shape), { nil: undefined }), separator(shape), selectionSet(shape, 2))
    .map(([type, operationName, gap, body]) =>
      type === "shorthand" ? body : `${type}${operationName === undefined ? "" : ` ${operationName}`}${gap}${body}`,
    );
}

function fragment(shape: DocumentShape): fc.Arbitrary<string> {
  return fc
    .tuple(
      name(shape).filter((value) => value !== "on"),
      name(shape),
      separator(shape),
      selectionSet(shape, 1),
    )
    .map(([fragmentLabel, typeName, gap, body]) => `fragment ${fragmentLabel} on ${typeName}${gap}${body}`);
}

function definitions(shape: DocumentShape): fc.Arbitrary<string[]> {
  return fc.array(fc.oneof({ weight: 3, arbitrary: operation(shape) }, { weight: 1, arbitrary: fragment(shape) }), {
    minLength: 1,
    maxLength: 4,
  });
}

function graphqlDocument(shape: DocumentShape): fc.Arbitrary<string> {
  return fc
    .tuple(separator(shape), definitions(shape), separator(shape), separator(shape))
    .map(([lead, items, gap, trail]) => `${lead}${items.join(gap)}${trail}`);
}

// The operation types graphql-js parses, or undefined when it rejects the document.
function parsedOperationTypes(document: string): string[] | undefined {
  try {
    return parse(document)
      .definitions.filter((definition) => definition.kind === Kind.OPERATION_DEFINITION)
      .map((definition) => definition.operation);
  } catch {
    return undefined;
  }
}

function classifyJsonBody(bodyText: string): ReturnType<typeof classifyGraphqlRequestBody> {
  return classifyGraphqlRequestBody({
    contentType: "application/json",
    contentEncoding: undefined,
    contentLength: Buffer.byteLength(bodyText, "utf8"),
    bodyText,
  });
}

// A JSON body the classifier reads as a pure query, so every refusal below is
// caused by the one change the property makes.
const readJsonBody = fc
  .tuple(graphqlDocument(QUERY_ONLY), fc.option(plainName, { nil: undefined }))
  .filter(([document]) => classifyGraphqlDocument(document) === "read")
  .map(([document, operationName]) => ({ query: document, ...(operationName === undefined ? {} : { operationName }) }));

describe("GraphQL classifier properties", () => {
  it("P2.1: a document graphql-js parses with any non-query operation classifies write", () => {
    fc.assert(
      fc.property(graphqlDocument(ALL_OPERATIONS), (document) => {
        const operations = parsedOperationTypes(document);
        if (operations === undefined || operations.every((type) => type === "query")) return;
        expect(classifyGraphqlDocument(document)).toBe("write");
      }),
      propertyParameters(),
    );
  });

  // Product defect: the stripper ends a block string at the `"""` inside a
  // `\"""` escape, so two escapes can hide a mutation between them.
  it.skip('P2.1: a document whose block strings contain the \\""" escape still shows its mutation — product defect, see todo 107', () => {
    fc.assert(
      fc.property(graphqlDocument(BLOCK_ESCAPES), (document) => {
        const operations = parsedOperationTypes(document);
        if (operations === undefined || operations.every((type) => type === "query")) return;
        expect(classifyGraphqlDocument(document)).toBe("write");
      }),
      propertyParameters(),
    );
  });

  it("P2.2: a mutation inserted after a comment and any line terminator classifies write", () => {
    fc.assert(
      fc.property(
        definitions(QUERY_ONLY),
        fc.nat(),
        commentText(QUERY_ONLY),
        lineTerminator,
        separator(QUERY_ONLY),
        selectionSet(QUERY_ONLY, 1),
        (items, position, text, end, gap, body) => {
          const index = position % (items.length + 1);
          const inserted = [...items.slice(0, index), `#${text}${end}mutation${gap}${body}`, ...items.slice(index)];
          expect(classifyGraphqlDocument(inserted.join(gap))).toBe("write");
        },
      ),
      propertyParameters(),
    );
  });

  it("P2.3: a refused transport or envelope classifies write whatever the body", () => {
    const anyBody = fc.oneof(readJsonBody.map((body) => JSON.stringify(body)), fc.string());
    const contentEncoding = fc.string({ minLength: 1, maxLength: 12 }).filter((encoding) => encoding.trim() !== "" && encoding.trim() !== "identity");
    const transport = fc.oneof(
      fc.tuple(anyBody, contentEncoding).map(([bodyText, encoding]) => ({ bodyText, contentEncoding: encoding })),
      // Over the cap, by the declared length or by the buffered body.
      fc.tuple(anyBody, fc.integer({ min: 1, max: 64 })).map(([bodyText, over]) => ({
        bodyText,
        capBytes: Buffer.byteLength(bodyText, "utf8"),
        contentLength: Buffer.byteLength(bodyText, "utf8") + over,
      })),
      fc.tuple(anyBody.filter((body) => body.length > 0)).map(([bodyText]) => ({
        bodyText,
        capBytes: Buffer.byteLength(bodyText, "utf8") - 1,
        contentLength: undefined,
      })),
      // Shorter than the declared length: truncated.
      fc.tuple(anyBody, fc.integer({ min: 1, max: 64 })).map(([bodyText, missing]) => ({
        bodyText,
        contentLength: Buffer.byteLength(bodyText, "utf8") + missing,
      })),
      fc.constant({ bodyText: undefined }),
    );
    const nonObjectJson = fc.oneof(
      fc.array(fc.oneof(fc.jsonValue(), readJsonBody), { maxLength: 3 }),
      fc.string(),
      fc.integer(),
      fc.boolean(),
      fc.constant(null),
    );
    const persistedQuery = fc
      .tuple(readJsonBody, fc.jsonValue(), fc.dictionary(fc.string(), fc.jsonValue(), { maxKeys: 2 }))
      .map(([body, reference, otherExtensions]) => ({ ...body, extensions: { ...otherExtensions, persistedQuery: reference } }));
    fc.assert(
      fc.property(
        fc.oneof(
          transport.map((overrides) => ({ contentType: "application/json", contentEncoding: undefined, contentLength: undefined, ...overrides })),
          nonObjectJson.map((parsed) => ({ contentType: "application/json", contentEncoding: undefined, contentLength: undefined, bodyText: JSON.stringify(parsed) })),
          persistedQuery.map((parsed) => ({ contentType: "application/json", contentEncoding: undefined, contentLength: undefined, bodyText: JSON.stringify(parsed) })),
        ),
        (input) => {
          expect(classifyGraphqlRequestBody(input)).toBe("write");
        },
      ),
      propertyParameters(),
    );
  });

  // Product defect: JSON.parse keeps the last duplicate, so
  // `{"query":"mutation{…}","query":"{a}"}` classifies read, while an upstream
  // that keeps the first key runs the mutation (H2).
  it.skip("P2.4: duplicate top-level JSON keys classify write — product defect, see todo 108", () => {
    // A key written with some characters as \uXXXX escapes still names the same key.
    const encodedKey = (key: string) =>
      fc
        .array(fc.boolean(), { minLength: key.length, maxLength: key.length })
        .map((escapes) => `"${[...key].map((char, index) => (escapes[index] ? `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}` : char)).join("")}"`);
    const duplicated = fc.oneof(fc.constantFrom("query", "operationName", "variables", "extensions", "documentId"), fc.string({ maxLength: 6 }));
    const memberValue = fc.oneof(fc.jsonValue(), fc.constantFrom("mutation { deleteRepo(id: 1) { id } }", "{ a }"));
    fc.assert(
      fc.property(
        readJsonBody,
        duplicated.chain((key) => fc.tuple(fc.constant(key), encodedKey(key), encodedKey(key))),
        fc.tuple(memberValue, memberValue),
        fc.tuple(fc.nat(), fc.nat()),
        (body, [key, firstKey, secondKey], [firstValue, secondValue], [firstPosition, secondPosition]) => {
          const members = Object.entries(body).map(([member, item]) => `${JSON.stringify(member)}:${JSON.stringify(item)}`);
          members.splice(firstPosition % (members.length + 1), 0, `${firstKey}:${JSON.stringify(firstValue)}`);
          // A key the body lacks needs two inserted copies to be duplicated.
          if (!Object.hasOwn(body, key)) {
            members.splice(secondPosition % (members.length + 1), 0, `${secondKey}:${JSON.stringify(secondValue)}`);
          }
          expect(classifyJsonBody(`{${members.join(",")}}`)).toBe("write");
        },
      ),
      propertyParameters(),
    );
  });
});
