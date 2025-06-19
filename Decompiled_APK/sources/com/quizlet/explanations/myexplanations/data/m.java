package com.quizlet.explanations.myexplanations.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class m extends o {
    public final String a;

    public m(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Question(id="), this.a, ")");
    }
}
