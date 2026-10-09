import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { propertyParameters } from "./property.js";

describe("propertyParameters", () => {
  it("defaults to 200 runs, a random seed, and a verbose failure report", () => {
    const parameters = propertyParameters({}, {});
    expect(parameters).toEqual({ verbose: 1, numRuns: 200 });
    expect(parameters.seed).toBeUndefined();
  });

  it("lets a property lower its default run count, but RUNFREE_PROP_RUNS wins", () => {
    expect(propertyParameters({ numRuns: 50 }, {}).numRuns).toBe(50);
    expect(propertyParameters({ numRuns: 50 }, { RUNFREE_PROP_RUNS: "100000" }).numRuns).toBe(100000);
  });

  it.each(["0", "-1", "1.5", "1e5", "one", " 200", "200 ", "99999999999999999999"])(
    "refuses RUNFREE_PROP_RUNS=%j instead of defaulting",
    (value) => {
      expect(() => propertyParameters({}, { RUNFREE_PROP_RUNS: value })).toThrow(/RUNFREE_PROP_RUNS must be a positive integer/);
    },
  );

  it("passes a printed seed through, including a negative one", () => {
    expect(propertyParameters({}, { RUNFREE_PROP_SEED: "1234567" }).seed).toBe(1234567);
    expect(propertyParameters({}, { RUNFREE_PROP_SEED: "-1786543210" }).seed).toBe(-1786543210);
  });

  it.each(["abc", "1.5", "0x10", "4294967296"])("refuses RUNFREE_PROP_SEED=%j", (value) => {
    expect(() => propertyParameters({}, { RUNFREE_PROP_SEED: value })).toThrow(/RUNFREE_PROP_SEED must be/);
  });

  it("passes a replay path through only with a seed", () => {
    expect(propertyParameters({}, { RUNFREE_PROP_SEED: "7", RUNFREE_PROP_PATH: "12:0:3" }).path).toBe("12:0:3");
    expect(() => propertyParameters({}, { RUNFREE_PROP_PATH: "12:0:3" })).toThrow(/needs RUNFREE_PROP_SEED/);
    expect(() => propertyParameters({}, { RUNFREE_PROP_SEED: "7", RUNFREE_PROP_PATH: "12;rm" })).toThrow(
      /RUNFREE_PROP_PATH must be a fast-check path/,
    );
  });

  it("replays the same generated values for the same seed", () => {
    const sample = (seed: string): number[] => {
      const seen: number[] = [];
      fc.assert(
        fc.property(fc.integer(), (value) => {
          seen.push(value);
        }),
        propertyParameters({ numRuns: 20 }, { RUNFREE_PROP_SEED: seed }),
      );
      return seen;
    };
    expect(sample("42")).toEqual(sample("42"));
    expect(sample("42")).not.toEqual(sample("43"));
  });

  it("reports the seed and shrink path of a failing property", () => {
    expect(() =>
      fc.assert(
        fc.property(fc.integer({ min: 0, max: 1000 }), (value) => value < 500),
        propertyParameters({}, { RUNFREE_PROP_SEED: "9" }),
      ),
    ).toThrow(/seed: 9, path: "[0-9:]+"[\s\S]*Counterexample: \[500\]/);
  });
});
