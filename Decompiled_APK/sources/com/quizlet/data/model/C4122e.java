package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4122e extends AbstractC4128g {
    public final Exception a;

    public C4122e(Exception exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4122e) && Intrinsics.b(this.a, ((C4122e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AchievementBadgeException(exception=" + this.a + ")";
    }
}
