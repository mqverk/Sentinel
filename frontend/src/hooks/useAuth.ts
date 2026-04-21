import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe, login } from "@/api/sentinel";
import { clearAuthToken, getAuthToken, setAuthToken } from "@/lib/auth";
import type { LoginResponse } from "@/types/api";

const ME_QUERY = ["auth", "me"];

export function useCurrentUser() {
  const token = getAuthToken();
  return useQuery({
    queryKey: ME_QUERY,
    queryFn: getMe,
    enabled: Boolean(token),
    staleTime: 60_000,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) => login(username, password),
    onSuccess: async (result: LoginResponse) => {
      setAuthToken(result.token);
      await queryClient.invalidateQueries({ queryKey: ME_QUERY });
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return () => {
    clearAuthToken();
    queryClient.clear();
  };
}
