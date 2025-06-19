package com.quizlet.features.questiontypes.fitb.ui;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements e {
    public final String a;

    public b(String correctAnswer) {
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        this.a = correctAnswer;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Correct(correctAnswer="), this.a, ")");
    }
}
