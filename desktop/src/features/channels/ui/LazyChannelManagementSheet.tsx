import * as React from "react";

export const LazyChannelManagementSheet = React.lazy(async () => {
  const module = await import("./ChannelManagementSheet");
  return { default: module.ChannelManagementSheet };
});
