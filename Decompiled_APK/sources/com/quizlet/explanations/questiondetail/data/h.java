package com.quizlet.explanations.questiondetail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h implements i {
    public final String a;

    public h(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.a = isbn;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Textbook(isbn="), this.a, ")");
    }
}
