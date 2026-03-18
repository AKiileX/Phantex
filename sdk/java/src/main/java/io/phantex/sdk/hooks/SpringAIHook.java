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
 * Hook for Spring AI (https://docs.spring.io/spring-ai/reference/).
 *
 * <p>Intercepts Spring AI model calls via dynamic proxy wrappers:
 * <ul>
 *   <li>ChatModel#call — chat completions</li>
 *   <li>EmbeddingModel#call — embedding requests</li>
 *   <li>FunctionCallback#call — tool/function calls</li>
 * </ul>
 *
 * <p>Since Spring AI is interface-driven, wrapping is clean:
 * <pre>
 *   var hook = new SpringAIHook(transport, config);
 *   ChatModel wrapped = hook.wrap(originalModel);
 * </pre>
 */
public class SpringAIHook extends BaseHook {

    private final List<Object> proxies = new ArrayList<>();

    public SpringAIHook(PhantexTransport.Transport transport, PhantexConfig config) {
        super(transport, config);
    }

    @Override public String name()      { return "spring_ai"; }
    @Override public String framework() { return "spring_ai"; }

    @Override
    public boolean install() {
        try {
            Class.forName("org.springframework.ai.chat.model.ChatModel");
            installed = true;
            if (config.debug()) LOG.info("[phantex] Spring AI hook ready");
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
     * Wrap a Spring AI model/callback to capture all calls.
     */
    @SuppressWarnings("unchecked")
    public <T> T wrap(T model) {
        if (!installed) return model;

        Class<?>[] interfaces = model.getClass().getInterfaces();
        if (interfaces.length == 0) return model;

        Object proxy = Proxy.newProxyInstance(
            model.getClass().getClassLoader(),
            interfaces,
            new SpringAIInvocationHandler(model)
        );
        proxies.add(proxy);
        return (T) proxy;
    }

    private class SpringAIInvocationHandler implements InvocationHandler {
        private final Object delegate;

        SpringAIInvocationHandler(Object delegate) {
            this.delegate = delegate;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String methodName = method.getName();

            if (isTrackedMethod(methodName)) {
                String className = delegate.getClass().getSimpleName();
                String toolName = "spring_ai." + className + "." + methodName;
                String[] span = emitToolCall(toolName, "spring_ai", args);
                String spanId = span[0];
                long startNs = Long.parseLong(span[1]);

                try {
                    Object result = method.invoke(delegate, args);
                    emitToolResponse(toolName, "spring_ai", spanId, startNs, true, null);
                    return result;
                } catch (Throwable t) {
                    Throwable cause = t.getCause() != null ? t.getCause() : t;
                    emitToolResponse(toolName, "spring_ai", spanId, startNs, false, cause.getMessage());
                    throw cause;
                }
            }

            return method.invoke(delegate, args);
        }

        private boolean isTrackedMethod(String name) {
            return "call".equals(name) || "stream".equals(name) || "embed".equals(name);
        }
    }
}
