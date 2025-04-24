import { z } from "zod";

const resultPoint = z.object({
  col: z.number().optional(),
  line: z.number().optional(),
  offset: z.number().optional(),
});

const oxWrapper = z.object({
  cwe: z.array(z.string()).optional(),
  severityFactors: z.array(z.string()).optional(),
  description: z.string().optional(),
  recommendation: z.string().optional(),
  title: z.string().optional(),
  severity: z.string().optional(),
  eduVideoLink: z.string().optional(),
});

const resultExtra = z.object({
  oxwrapper: oxWrapper.optional(),
  message: z.string().optional(),
  lines: z.string().optional(),
  severity: z.string().optional(),
  metavars: z.record(
    z
      .object({
        abstract_content: z.string().optional(),
        end: resultPoint.optional(),
        start: resultPoint.optional(),
      })
      .optional(),
  ),
});

export const semgrepSchema = z.object({
  results: z.array(
    z.object({
      check_id: z.string().optional(),
      start: resultPoint.optional(),
      end: resultPoint.optional(),
      path: z.string().optional(),
      extra: resultExtra.optional(),
    }),
  ),
});
export type SemgrepResults = z.infer<typeof semgrepSchema>;
