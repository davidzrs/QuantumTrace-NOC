import { useMutation, useQueryClient } from "@tanstack/react-query";
import { accountState, removeScans } from "./account";
import { api } from "./api";
import { forget } from "./history";

/**
 * Delete scans from the API, then drop them from this browser's history and, when signed in, from
 * the account's: the report is gone for everyone holding the link. Fails with how many didn't go.
 */
export function useDeleteScans() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => api.deleteScan(id)));
      const deleted = ids.filter((_, i) => results[i]?.status === "fulfilled");
      forget(deleted);
      if (accountState().status === "signed-in") await removeScans(deleted).catch(() => undefined);
      for (const id of deleted) queryClient.removeQueries({ queryKey: ["scan", id] });
      if (deleted.length < ids.length) {
        throw new Error(`${ids.length - deleted.length} of ${ids.length} scans couldn’t be deleted`);
      }
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });
}
