package com.quizlet.search.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends l {
    public final String a;

    public d(String questionId) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        this.a = questionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Question(questionId="), this.a, ")");
    }
}
