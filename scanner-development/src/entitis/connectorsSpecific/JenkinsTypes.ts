import { z } from "zod";

//
// Declare the schema for the Jenkins Job config
//

export const jobSchema = z.object({
  "flow-definition": z.object({
    actions: z.any({}).optional(),
    description: z.string().optional(),
    keepDependencies: z.boolean().optional(),
    properties: z.any().optional(),
    definition: z.object({
      scm: z.object({
        configVersion: z.number().optional(),
        userRemoteConfigs: z.object({
          "hudson.plugins.git.UserRemoteConfig": z.object({
            url: z.string(),
          }),
        }),
        branches: z.object({
          "hudson.plugins.git.BranchSpec": z.object({
            name: z.string(),
          }),
        }),
        doGenerateSubmoduleConfigurations: z.boolean().optional(),
        submoduleCfg: z.any().optional(),
        extensions: z.any().optional(),
      }),
      scriptPath: z.string(),
      lightweight: z.boolean().optional(),
    }),
    triggers: z.any().optional(),
    disabled: z.boolean().optional(),
  }),
});

export type jenkinsJob = z.infer<typeof jobSchema>;

export const newJobSchema = z.object({
  name: z.string(),
  fullName: z.string(),
  builds: z.array(
    z.object({
      number: z.number(),
      url: z.string(),
    }),
  ),
});

export type newJenkinsJob = z.infer<typeof newJobSchema>;

export const freeStyleProject = z.object({
  project: z.object({
    displayName: z.string(),
    scm: z.object({
      branches: z.object({
        "hudson.plugins.git.BranchSpec": z.object({
          name: z.string(),
        }),
      }),
    }),
  }),
});

export type freeStyleJob = z.infer<typeof freeStyleProject>;
//
// Job schema
//

export const buildJobSchema = z.object({
  _class: z.string().optional(),
  actions: z.array(z.object({})).optional(),
  description: z.string().optional(),
  displayName: z.string().optional(),
  displayNameOrNull: z.any().optional(),
  name: z.string().optional(),
  fullDisplayName: z.string().optional(),
  fullName: z.string().optional(),
  url: z.string().optional(),
  buildable: z.boolean().optional(),
  builds: z.array(
    z.object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    }),
  ),
  color: z.string().optional(),
  firstBuild: z.object({}).optional(),
  healthReport: z.array(z.object({})).optional(),
  inQueue: z.boolean().optional(),
  keepDependencies: z.boolean().optional(),
  lastBuild: z.object({}).optional(),
  lastCompletedBuild: z
    .object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    })
    .optional(),
  lastFailedBuild: z
    .object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    })
    .optional(),
  lastStableBuild: z.object({}).optional(),
  lastSuccessfulBuild: z
    .object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    })
    .optional(),
  lastUnstableBuild: z.any().optional(),
  lastUnsuccessfulBuild: z.object({}).optional(),
  nextBuildNumber: z.number().optional(),
  property: z.array(z.object({})).optional(),
  queueItem: z.any().optional(),
  concurrentBuild: z.boolean().optional(),
  resumeBlocked: z.boolean().optional(),
});

export type buildJob = z.infer<typeof buildJobSchema>;

export const newBuildJobSchema = z.object({
  builds: z.array(
    z.object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    }),
  ),
  lastSuccessfulBuild: z
    .object({
      _class: z.string().optional(),
      number: z.number().optional(),
      url: z.string().optional(),
    })
    .optional(),
});

export type newBuildJob = z.infer<typeof newBuildJobSchema>;

//
// Job list schema
//
export const jobsListSchema = z.array(
  z.object({
    _class: z.string().optional(),
    name: z.string(),
    url: z.string().optional(),
    color: z.string().optional(),
  }),
);

export type jobsList = z.infer<typeof jobsListSchema>;

export const updateServerUrl = (url: string, jobUrl: string) => {
  try {
    const jobSeparator = jobUrl.indexOf("/job");
    if (jobSeparator !== -1) {
      if (url === jobUrl.substring(0, jobSeparator)) {
        return jobUrl;
      } else {
        return url + jobUrl.substring(jobSeparator);
      }
    }
  } catch (err) {
    return jobUrl;
  }
  return jobUrl;
};
