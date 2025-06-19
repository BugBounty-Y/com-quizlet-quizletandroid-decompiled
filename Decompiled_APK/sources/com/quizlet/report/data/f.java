package com.quizlet.report.data;

/* loaded from: classes3.dex */
public final class f implements h {
    public final int a;

    public f(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && this.a == ((f) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("PrimaryButtonClicked(index="), this.a, ")");
    }
}
