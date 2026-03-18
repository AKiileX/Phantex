package io.phantex.sdk;

/**
 * Hook interface — all framework hooks implement this.
 */
public interface PhantexHook {

    /** Hook name (e.g. "langchain4j", "spring_ai"). */
    String name();

    /** Framework name (e.g. "langchain4j", "spring_ai"). */
    String framework();

    /**
     * Install the hook. Returns true if the framework is available and patching succeeded.
     */
    boolean install();

    /** Uninstall the hook, restoring original behaviour. */
    void uninstall();

    /** Whether the hook is currently installed. */
    boolean isInstalled();
}
