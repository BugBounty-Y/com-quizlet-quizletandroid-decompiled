package org.wordpress.aztec.formatting;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final int b;

    public a(boolean z, int i) {
        this.a = z;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExclusiveBlockStyles(enabled=");
        sb.append(this.a);
        sb.append(", verticalParagraphMargin=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
