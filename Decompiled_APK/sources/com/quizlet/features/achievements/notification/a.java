package com.quizlet.features.achievements.notification;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends c {
    public final com.quizlet.features.achievements.achievement.a a;

    public a(com.quizlet.features.achievements.achievement.a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Earned(data=" + this.a + ")";
    }
}
