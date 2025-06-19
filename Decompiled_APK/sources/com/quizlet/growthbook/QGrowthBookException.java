package com.quizlet.growthbook;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QGrowthBookException extends RuntimeException {
    public final String a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public QGrowthBookException(String message) {
        super(message);
        Intrinsics.checkNotNullParameter(message, "message");
        this.a = message;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
