package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4134i extends AbstractC4140k {
    public final Exception a;

    public C4134i(Exception exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4134i) && Intrinsics.b(this.a, ((C4134i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AchievementBadgesException(exception=" + this.a + ")";
    }
}
