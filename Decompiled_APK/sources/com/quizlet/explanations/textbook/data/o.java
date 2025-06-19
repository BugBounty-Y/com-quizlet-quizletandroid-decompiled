package com.quizlet.explanations.textbook.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o extends p {
    public final String a;

    public o(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.a = isbn;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && Intrinsics.b(this.a, ((o) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("TableOfContents(isbn="), this.a, ")");
    }
}
