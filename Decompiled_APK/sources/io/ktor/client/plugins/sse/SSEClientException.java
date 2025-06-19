package io.ktor.client.plugins.sse;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class SSEClientException extends IllegalStateException {
    public final Throwable a = null;
    public final String b = null;

    @Override // java.lang.Throwable
    public final Throwable getCause() {
        return this.a;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.b;
    }
}
