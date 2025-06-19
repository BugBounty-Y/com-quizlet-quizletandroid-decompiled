package org.wordpress.aztec.formatting;

/* loaded from: classes3.dex */
public final class o {
    public final int a;
    public final boolean b;

    public o(int i, boolean z) {
        this.a = i;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LinkStyle(linkColor=");
        sb.append(this.a);
        sb.append(", linkUnderline=");
        return android.support.v4.media.session.a.u(sb, this.b, ')');
    }
}
