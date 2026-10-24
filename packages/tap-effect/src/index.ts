export { TapFailure, toTapFailure } from "./errors.js";
export {
  ActivationSchema,
  AlgorithmSchema,
  IntentTagSchema,
  ProfileSchema,
  RegistryKeySchema,
  VerifiedAgentSchema,
  type RegistryKeyDocument,
  type VerifiedAgentDocument,
} from "./schema.js";
export {
  KeyResolverService,
  ReplayStoreService,
  TapClientService,
  TapVerifierService,
  cachingRegistryResolverLayer,
  memoryReplayLayer,
  sqliteReplayLayer,
  tapClientLayer,
  tapVerifierFromPromises,
  tapVerifierLayer,
  type RegistryResolverConfig,
  type VerifierLayerConfig,
} from "./services.js";
