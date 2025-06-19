package kotlinx.coroutines.internal;

import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;

@Metadata
/* loaded from: classes3.dex */
public final class DiagnosticCoroutineContextException extends RuntimeException {
    public final transient CoroutineContext a;

    public DiagnosticCoroutineContextException(CoroutineContext coroutineContext) {
        this.a = coroutineContext;
    }

    @Override // java.lang.Throwable
    public final Throwable fillInStackTrace() {
        setStackTrace(new StackTraceElement[0]);
        return this;
    }

    @Override // java.lang.Throwable
    public final String getLocalizedMessage() {
        return String.valueOf(this.a);
    }
}
