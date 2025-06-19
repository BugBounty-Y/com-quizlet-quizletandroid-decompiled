package com.quizlet.features.home.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements r {
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
        return android.support.v4.media.session.a.t(new StringBuilder("Textbook(isbn="), this.a, ")");
    }
}
