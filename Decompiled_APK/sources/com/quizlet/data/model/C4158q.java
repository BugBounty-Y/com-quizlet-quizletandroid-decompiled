package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4158q extends AbstractC4163s {
    public final Exception a;

    public C4158q(Exception exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4158q) && Intrinsics.b(this.a, ((C4158q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AchievementsHistoryException(exception=" + this.a + ")";
    }
}
