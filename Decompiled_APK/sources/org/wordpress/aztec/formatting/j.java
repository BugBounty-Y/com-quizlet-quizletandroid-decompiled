package org.wordpress.aztec.formatting;

/* loaded from: classes3.dex */
public final class j {
    public final int a;
    public final float b;
    public final int c;

    public j(int i, float f, int i2) {
        this.a = i;
        this.b = f;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && Float.compare(this.b, jVar.b) == 0 && this.c == jVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + android.support.v4.media.session.a.b(Integer.hashCode(this.a) * 31, this.b, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CodeStyle(codeBackground=");
        sb.append(this.a);
        sb.append(", codeBackgroundAlpha=");
        sb.append(this.b);
        sb.append(", codeColor=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
