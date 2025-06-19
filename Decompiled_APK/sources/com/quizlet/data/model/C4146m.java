package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4146m extends AbstractC4152o {
    public final Exception a;

    public C4146m(Exception exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4146m) && Intrinsics.b(this.a, ((C4146m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AchievementNotificationException(exception=" + this.a + ")";
    }
}
