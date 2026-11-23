import { createContext, useContext } from "react";
import type { Meta } from "../api/types.ts";

const MetaContext = createContext<Meta | null>(null);
export const MetaProvider = MetaContext.Provider;

export function useMeta(): Meta {
  const m = useContext(MetaContext);
  if (!m) throw new Error("useMeta 需要在 MetaProvider 内使用");
  return m;
}
