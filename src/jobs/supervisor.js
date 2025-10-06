export function createJobSupervisor(name, logger) {
  let running = false;
  let lastStartedAt = null;
  let lastFinishedAt = null;

  return {
    async run(fn) {
      if (running) {
        logger?.warn({ job: name }, "Job already running; skipping");
        return;
      }
      running = true;
      lastStartedAt = Date.now();
      logger?.info({ job: name, startedAt: lastStartedAt }, "Job started");
      try {
        await fn();
      } catch (e) {
        logger?.error({ job: name, err: e?.message || e }, "Job error");
      } finally {
        lastFinishedAt = Date.now();
        logger?.info({ job: name, finishedAt: lastFinishedAt, durationMs: lastFinishedAt - lastStartedAt }, "Job finished");
        running = false;
      }
    },
    isRunning() { return running; },
    getLastRun() { return { startedAt: lastStartedAt, finishedAt: lastFinishedAt }; }
  };
}
