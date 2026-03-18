package io.phantex.sdk.hooks;

import io.phantex.sdk.BaseHook;
import io.phantex.sdk.PhantexConfig;
import io.phantex.sdk.PhantexTransport;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * Hook for LangChain4j (https://github.com/langchain4j/langchain4j).
 *
 * <p>Intercepts via callback/listener pattern:
 * <ul>
 *   <li>ChatLanguageModel — chat completions</li>
 *   <li>Tool execution callbacks</li>
 * </ul>
 *
 * <p>Since Java doesn't support monkey-patching, this hook works by providing
 * wrapper/decorator factories that users apply to their LangChain4j components.
 *
 * <p>Usage:
 * <pre>
 *   var hook = new LangChain4jHook(transport, config);
 *   ChatLanguageModel wrapped = hook.wrap(originalModel);
 * </pre>
 */
public class LangChain4jHook extends BaseHook {

    private final List<Object> proxies = new ArrayList<>();

    public LangChain4jHook(PhantexTransport.Transport transport, PhantexConfig config) {
        super(transport, config);
    }

    @Override public String name()      { return "langchain4j"; }
    @Override public String framework() { return "langchain4j"; }

    @Override
    public boolean install() {
        // Check if LangChain4j is on the classpath
        try {
            Class.forName("dev.langchain4j.model.chat.ChatLanguageModel");
            installed = true;
            if (config.debug()) LOG.info("[phantex] LangChain4j hook ready");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @Override
    public void uninstall() {
        proxies.clear();
        installed = false;
    }

    /**
     * Wrap a ChatLanguageModel to capture all chat calls.
     * Returns a proxied version that emits Phantex events.
     */
    @SuppressWarnings("unchecked")
    public <T> T wrap(T model) {
        if (!installed) return model;

        Class<?>[] interfaces = model.getClass().getInterfaces();
        if (interfaces.length == 0) return model;

        Object proxy = Proxy.newProxyInstance(
            model.getClass().getClassLoader(),
            interfaces,
            new PhantexInvocationHandler(model)
        );
        proxies.add(proxy);
        return (T) proxy;
    }

    private class PhantexInvocationHandler implements InvocationHandler {
        private final Object delegate;

        PhantexInvocationHandler(Object delegate) {
            this.delegate = delegate;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String methodName = method.getName();

            // Only intercept AI-relevant methods
            if (isTrackedMethod(methodName)) {
                String toolName = "langchain4j." + delegate.getClass().getSimpleName() + "." + methodName;
                String[] span = emitToolCall(toolName, "langchain4j", args);
                String spanId = span[0];
                long startNs = Long.parseLong(span[1]);

                try {
                    Object result = method.invoke(delegate, args);
                    emitToolResponse(toolName, "langchain4j", spanId, startNs, true, null);
                    return result;
                } catch (Throwable t) {
                    Throwable cause = t.getCause() != null ? t.getCause() : t;
                    emitToolResponse(toolName, "langchain4j", spanId, startNs, false, cause.getMessage());
                    throw cause;
                }
            }

            return method.invoke(delegate, args);
        }

        private boolean isTrackedMethod(String name) {
            return "generate".equals(name) || "chat".equals(name) ||
                   "execute".equals(name) || "run".equals(name) ||
                   "call".equals(name) || "invoke".equals(name);
        }
    }
}
