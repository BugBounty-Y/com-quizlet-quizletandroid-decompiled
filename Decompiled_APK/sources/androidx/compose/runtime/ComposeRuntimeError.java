package androidx.compose.runtime;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ComposeRuntimeError extends IllegalStateException {
    public final String a;

    public ComposeRuntimeError(String str) {
        this.a = str;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
