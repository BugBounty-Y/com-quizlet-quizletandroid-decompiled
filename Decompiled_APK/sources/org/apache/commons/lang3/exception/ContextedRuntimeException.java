package org.apache.commons.lang3.exception;

import kotlin.C4939h;

/* loaded from: classes3.dex */
public class ContextedRuntimeException extends RuntimeException {
    public final C4939h a = new C4939h();

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a.a(super.getMessage());
    }
}
