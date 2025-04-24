describe("Find images by regular expression", () => {
  it("Test lambda name by regex by image", () => {
    const lambdaNames = [
      "com_stage_eu-west-1_web_real_sport-SI-context_lf",
      "com_siteedit_eu-west-1_web_real_nooff-SI-context_lf",
      "com_stage_eu-west-1_web_real_casino-SI-context_lf",
      "com_prod_eu-west-1_web_real_sport-SI-context_lf",
      "com_siteedit_eu-west-1_web_real_poker-SI-context_lf",
      "com_stage_eu-west-1_web_real_nooff-SI-context_lf",
      "com_prod_eu-west-1_web_real_poker-SI-context_lf",
      "com_stage_eu-west-1_web_real_poker-SI-context_lf",
    ];

    const regExImage: Map<string, string> = new Map();
    const regName = "${Market}_${Environment}_${AWS::Region}_${Vertical}_${FunctionalLevel}_${Offering}-SI-context${Suffix}_lf".replace(
      /\$\{[_\-:a-zA-Z0-9]+\}/gm,
      "([\\-a-zA-Z0-9]*)",
    );
    regExImage.set(regName, "test1");

    console.log(regName);

    for (const lambdaName of lambdaNames) {
      for (const [regExKey, cicd] of regExImage) {
        const regex = new RegExp(regExKey, "g");
        const match = regex.exec(lambdaName);
        if (match != null) {
          expect(match[0] === lambdaName).toBeTruthy();
        } else {
          expect(true).toBeFalsy();
        }
      }
    }
  });

  it("Test lambda name by regex by image II", () => {
    const lambdaNames = [
      "com_siteedit_eu-west-1_web_real_nooff-SI-redirectionsrules_lf",
      "com_stage_eu-west-1_web_real_nooff-SI-redirections_lf",
      "com_stage_eu-west-1_web_real_poker-SI-redirectionsrules_lf",
      "com_prod_eu-west-1_web_real_poker-SI-redirectionsrules_lf",
      "com_siteedit_eu-west-1_web_real_poker-SI-redirectionsrules_lf",
      "com_prod_eu-west-1_web_real_poker-SI-redirections_lf",
      "com_prod_eu-west-1_web_real_nooff-SI-redirectionsrules_lf",
      "com_siteedit_eu-west-1_web_real_sport-SI-redirectionsrules_lf",
      "com_siteedit_eu-west-1_web_real_casino-SI-redirections_lf",
      "com_prod_eu-west-1_web_real_nooff-SI-redirections_lf",
      "com_prod_eu-west-1_web_real_sport-SI-redirections_lf",
    ];

    const regExImage: Map<string, string> = new Map();
    const regName =
      "${Market}_${Environment}_${AWS::Region}_${Vertical}_${FunctionalLevel}_${Offering}-SI-redirections${Suffix}_lf".replace(
        /\$\{[_\-:a-zA-Z0-9]+\}/gm,
        "([\\-a-zA-Z0-9]*)",
      );
    regExImage.set(regName, "test1");

    console.log(regName);

    for (const lambdaName of lambdaNames) {
      for (const [regExKey, cicd] of regExImage) {
        const regex = new RegExp(regExKey, "g");
        const match = regex.exec(lambdaName);
        if (match != null) {
          expect(match[0] === lambdaName).toBeTruthy();
        } else {
          expect(true).toBeFalsy();
        }
      }
    }
  });
});
