import { SSTConfig } from "sst";
import { TinyCloudStack } from "./stacks/TinyCloudStack";

export default {
  config(_input) {
    return {
      name: "tinycloud",
      region: "us-east-1",
    };
  },
  stacks(app) {
    app.stack(TinyCloudStack);
  }
} satisfies SSTConfig;