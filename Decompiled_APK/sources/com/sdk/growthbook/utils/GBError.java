package com.sdk.growthbook.utils;

import kotlin.C4937f;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBError {

    @NotNull
    private final String errorMessage;
    private final String stackTrace;

    public GBError(Throwable th) {
        String message;
        this.errorMessage = (th == null || (message = th.getMessage()) == null) ? "" : message;
        this.stackTrace = th != null ? C4937f.b(th) : null;
    }

    @NotNull
    public final String getErrorMessage() {
        return this.errorMessage;
    }

    public final String getStackTrace() {
        return this.stackTrace;
    }
}
