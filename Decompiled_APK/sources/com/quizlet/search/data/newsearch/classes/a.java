package com.quizlet.search.data.newsearch.classes;

import com.quizlet.data.model.C4136i1;
import com.quizlet.search.data.newsearch.b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements b {
    public final C4136i1 a;

    public a(C4136i1 data) {
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
        return "NewSearchClass(data=" + this.a + ")";
    }
}
