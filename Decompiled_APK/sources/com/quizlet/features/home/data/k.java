package com.quizlet.features.home.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements r {
    public final String a;

    public k(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.a = uuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.a, ((k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTests(uuid="), this.a, ")");
    }
}
