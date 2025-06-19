package com.quizlet.search.data.newsearch.explanations;

import com.quizlet.data.model.Z;
import com.quizlet.search.data.newsearch.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements c {
    public final Z a;

    public a(Z data) {
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
        return "NewSearchExplanations(data=" + this.a + ")";
    }
}
