package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y extends D {
    public final String a;

    public y(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.a = isbn;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && Intrinsics.b(this.a, ((y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToTextbook(isbn="), this.a, ")");
    }
}
