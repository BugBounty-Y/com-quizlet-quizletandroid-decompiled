package com.quizlet.explanations.questiondetail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g implements i {
    public final String a;

    public g(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Search(query="), this.a, ")");
    }
}
