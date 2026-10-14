import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import { settingsApi } from "@/lib/api/settings";
import { toast } from "@/lib/toast";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";

export function Http400RetryConfigPanel() {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState(false);
  const [maxRetries, setMaxRetries] = useState("3");
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [loadError, setLoadError] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    settingsApi
      .getHttp400RetryConfig()
      .then((config) => {
        if (cancelled) return;
        setEnabled(config.enabled);
        setMaxRetries(String(config.maxRetries));
      })
      .catch((error) => {
        if (!cancelled) setLoadError(String(error));
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const save = async () => {
    const value = Number(maxRetries);
    if (
      !/^\d+$/.test(maxRetries.trim()) ||
      !Number.isInteger(value) ||
      value < 0 ||
      value > 10
    ) {
      toast.error(t("http400Retry.invalidMaxRetries"));
      return;
    }
    setIsSaving(true);
    try {
      await settingsApi.setHttp400RetryConfig({
        enabled,
        maxRetries: value,
      });
      toast.success(t("http400Retry.saved"));
    } catch (error) {
      toast.error(`${t("http400Retry.saveFailed")}: ${String(error)}`);
    } finally {
      setIsSaving(false);
    }
  };

  const disabled = isLoading || isSaving || loadError !== undefined;

  return (
    <div className="space-y-4">
      <p className="text-sm text-fg-2">{t("http400Retry.description")}</p>
      {loadError !== undefined && (
        <Alert variant="destructive">
          <AlertDescription>
            {t("http400Retry.loadFailed")}: {loadError}
          </AlertDescription>
        </Alert>
      )}
      <div className="flex items-center justify-between gap-4">
        <Label htmlFor="http400-retry-enabled">
          {t("http400Retry.enabled")}
        </Label>
        <Switch
          id="http400-retry-enabled"
          checked={enabled}
          onCheckedChange={setEnabled}
          disabled={disabled}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="http400-max-retries">
          {t("http400Retry.maxRetries")}
        </Label>
        <Input
          id="http400-max-retries"
          type="number"
          min={0}
          max={10}
          step={1}
          value={maxRetries}
          onChange={(event) => setMaxRetries(event.target.value)}
          disabled={disabled || !enabled}
          aria-describedby="http400-retry-hint"
          className="max-w-40"
        />
        <p id="http400-retry-hint" className="text-xs text-fg-2">
          {t("http400Retry.hint")}
        </p>
      </div>
      <div className="flex justify-end">
        <Button onClick={() => void save()} disabled={disabled}>
          {(isLoading || isSaving) && (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          )}
          {t("common.save")}
        </Button>
      </div>
    </div>
  );
}
