package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends D {
    public final String a;

    public z(String exerciseId) {
        Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
        this.a = exerciseId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && Intrinsics.b(this.a, ((z) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToTextbookExercise(exerciseId="), this.a, ")");
    }
}
