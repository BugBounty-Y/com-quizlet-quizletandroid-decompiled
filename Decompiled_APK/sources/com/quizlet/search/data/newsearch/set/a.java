package com.quizlet.search.data.newsearch.set;

import com.quizlet.data.model.C4113b2;
import com.quizlet.search.data.newsearch.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final C4113b2 a;

    public a(C4113b2 data) {
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
        return "NewSearchStudySet(data=" + this.a + ")";
    }
}
