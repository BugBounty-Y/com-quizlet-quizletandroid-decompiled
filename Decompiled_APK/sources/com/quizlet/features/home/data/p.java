package com.quizlet.features.home.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements r {
    public final String a;

    public p(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && Intrinsics.b(this.a, ((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("TextbookExercise(id="), this.a, ")");
    }
}
