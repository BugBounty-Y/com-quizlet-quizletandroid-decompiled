package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends F {
    public final String a;

    public D(String exerciseId) {
        Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
        this.a = exerciseId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof D) && Intrinsics.b(this.a, ((D) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("TextbookExercise(exerciseId="), this.a, ")");
    }
}
