package com.quizlet.features.notes.common.events;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.notes.common.events.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4371b implements y {
    public final com.quizlet.features.notes.data.x a;

    public C4371b(com.quizlet.features.notes.data.x errorReason) {
        Intrinsics.checkNotNullParameter(errorReason, "errorReason");
        this.a = errorReason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4371b) && Intrinsics.b(this.a, ((C4371b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ErrorCtaButtonClicked(errorReason=" + this.a + ")";
    }
}
