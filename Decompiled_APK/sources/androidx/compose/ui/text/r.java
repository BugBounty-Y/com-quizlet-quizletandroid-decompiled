package androidx.compose.ui.text;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class r {
    public final androidx.compose.ui.text.platform.c a;
    public final int b;
    public final int c;

    public r(androidx.compose.ui.text.platform.c cVar, int i, int i2) {
        this.a = cVar;
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a.equals(rVar.a) && this.b == rVar.b && this.c == rVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ParagraphIntrinsicInfo(intrinsics=");
        sb.append(this.a);
        sb.append(", startIndex=");
        sb.append(this.b);
        sb.append(", endIndex=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
