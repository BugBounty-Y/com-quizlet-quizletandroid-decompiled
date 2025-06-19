package org.wordpress.aztec.formatting;

/* loaded from: classes3.dex */
public final class k {
    public final int a;

    public k(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && this.a == ((k) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("HighlightStyle(color="), this.a, ')');
    }
}
