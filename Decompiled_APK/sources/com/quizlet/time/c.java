package com.quizlet.time;

/* loaded from: classes3.dex */
public final class c {
    public final int a;

    public c(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a == ((c) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("ZeroIndexedMonth(value="), this.a, ")");
    }
}
