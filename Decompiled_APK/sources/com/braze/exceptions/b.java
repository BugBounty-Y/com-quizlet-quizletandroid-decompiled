package com.braze.exceptions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(String message, Exception innerException) {
        super(message, innerException);
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(innerException, "innerException");
    }
}
