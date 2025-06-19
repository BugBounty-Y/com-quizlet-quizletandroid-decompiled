package com.quizlet.explanations.textbook.chaptermenu.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g extends a {
    public final String a;

    public g(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToExercise(id="), this.a, ")");
    }
}
