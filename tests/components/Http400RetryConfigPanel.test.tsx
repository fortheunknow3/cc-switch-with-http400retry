import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Http400RetryConfigPanel } from "@/components/settings/Http400RetryConfigPanel";
import { settingsApi } from "@/lib/api/settings";
import { toast } from "@/lib/toast";

vi.mock("@/lib/api/settings", () => ({
  settingsApi: {
    getHttp400RetryConfig: vi.fn(),
    setHttp400RetryConfig: vi.fn(),
  },
}));

vi.mock("@/lib/toast", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

describe("Http400RetryConfigPanel", () => {
  beforeEach(() => {
    vi.mocked(settingsApi.getHttp400RetryConfig).mockResolvedValue({
      enabled: false,
      maxRetries: 3,
    });
    vi.mocked(settingsApi.setHttp400RetryConfig).mockResolvedValue(true);
  });

  const load = async () => {
    render(<Http400RetryConfigPanel />);
    const toggle = screen.getByRole("switch", { name: "http400Retry.enabled" });
    await waitFor(() => expect(toggle).toBeEnabled());
    return toggle;
  };

  it("loads persisted settings and saves the manual switch and retry count together", async () => {
    const toggle = await load();
    const count = screen.getByRole("spinbutton");
    expect(toggle).not.toBeChecked();
    expect(count).toBeDisabled();
    expect(count).toHaveValue(3);

    fireEvent.click(toggle);
    fireEvent.change(count, { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));

    await waitFor(() => {
      expect(settingsApi.setHttp400RetryConfig).toHaveBeenCalledWith({
        enabled: true,
        maxRetries: 5,
        diagnosticsEnabled: false,
      });
      expect(toast.success).toHaveBeenCalled();
    });
  });

  it("turns retries off without discarding the saved retry count", async () => {
    vi.mocked(settingsApi.getHttp400RetryConfig).mockResolvedValue({
      enabled: true,
      maxRetries: 7,
    });
    const toggle = await load();
    expect(toggle).toBeChecked();
    fireEvent.click(toggle);
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));
    await waitFor(() =>
      expect(settingsApi.setHttp400RetryConfig).toHaveBeenCalledWith({
        enabled: false,
        maxRetries: 7,
        diagnosticsEnabled: false,
      }),
    );
  });

  it.each(["", "-1", "11", "1.5"])(
    "rejects invalid retry count %j",
    async (value) => {
      fireEvent.click(await load());
      fireEvent.change(screen.getByRole("spinbutton"), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "common.save" }));
      expect(settingsApi.setHttp400RetryConfig).not.toHaveBeenCalled();
      expect(toast.error).toHaveBeenCalledWith(
        "http400Retry.invalidMaxRetries",
      );
    },
  );

  it.each([0, 10])("accepts the boundary value %i", async (maxRetries) => {
    fireEvent.click(await load());
    fireEvent.change(screen.getByRole("spinbutton"), {
      target: { value: String(maxRetries) },
    });
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));
    await waitFor(() =>
      expect(settingsApi.setHttp400RetryConfig).toHaveBeenCalledWith({
        enabled: true,
        maxRetries,
        diagnosticsEnabled: false,
      }),
    );
  });

  it("reports a save failure and allows another attempt", async () => {
    vi.mocked(settingsApi.setHttp400RetryConfig).mockRejectedValueOnce(
      new Error("disk full"),
    );
    await load();
    const save = screen.getByRole("button", { name: "common.save" });
    fireEvent.click(save);
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        expect.stringContaining("disk full"),
      ),
    );
    expect(toast.success).not.toHaveBeenCalled();
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
  });

  it("blocks writes if the saved settings could not be loaded", async () => {
    vi.mocked(settingsApi.getHttp400RetryConfig).mockRejectedValueOnce(
      new Error("database unavailable"),
    );
    render(<Http400RetryConfigPanel />);
    await screen.findByText(/database unavailable/);
    expect(
      screen.getByRole("switch", { name: "http400Retry.enabled" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("switch", { name: "http400Retry.diagnosticsEnabled" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "common.save" })).toBeDisabled();
  });

  it("saves diagnostics independently while automatic retries are disabled", async () => {
    const retryToggle = await load();
    const diagnostics = screen.getByRole("switch", {
      name: "http400Retry.diagnosticsEnabled",
    });
    expect(retryToggle).not.toBeChecked();
    expect(diagnostics).not.toBeChecked();
    expect(diagnostics).toBeEnabled();
    fireEvent.click(diagnostics);
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));
    await waitFor(() =>
      expect(settingsApi.setHttp400RetryConfig).toHaveBeenCalledWith({
        enabled: false,
        maxRetries: 3,
        diagnosticsEnabled: true,
      }),
    );
  });

  it("loads and preserves an existing diagnostics setting", async () => {
    vi.mocked(settingsApi.getHttp400RetryConfig).mockResolvedValue({
      enabled: true,
      maxRetries: 4,
      diagnosticsEnabled: true,
    });
    const retryToggle = await load();
    expect(
      screen.getByRole("switch", { name: "http400Retry.diagnosticsEnabled" }),
    ).toBeChecked();
    fireEvent.click(retryToggle);
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));
    await waitFor(() =>
      expect(settingsApi.setHttp400RetryConfig).toHaveBeenCalledWith({
        enabled: false,
        maxRetries: 4,
        diagnosticsEnabled: true,
      }),
    );
  });
});
