package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;

/* loaded from: classes.dex */
public final class q {
    public final C0982b a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final float f;
    public final float g;

    public q(C0982b c0982b, int i, int i2, int i3, int i4, float f, float f2) {
        this.a = c0982b;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = f;
        this.g = f2;
    }

    public final long a(long j, boolean z) {
        if (z) {
            long j2 = K.b;
            if (K.a(j, j2)) {
                return j2;
            }
        }
        int i = K.c;
        int i2 = (int) (j >> 32);
        int i3 = this.b;
        return AbstractC3205m5.c(i2 + i3, ((int) (j & 4294967295L)) + i3);
    }

    public final int b(int i) {
        int i2 = this.c;
        int i3 = this.b;
        return kotlin.ranges.l.c(i, i3, i2) - i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a.equals(qVar.a) && this.b == qVar.b && this.c == qVar.c && this.d == qVar.d && this.e == qVar.e && Float.compare(this.f, qVar.f) == 0 && Float.compare(this.g, qVar.g) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.g) + android.support.v4.media.session.a.b(d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31), 31), this.f, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ParagraphInfo(paragraph=");
        sb.append(this.a);
        sb.append(", startIndex=");
        sb.append(this.b);
        sb.append(", endIndex=");
        sb.append(this.c);
        sb.append(", startLineIndex=");
        sb.append(this.d);
        sb.append(", endLineIndex=");
        sb.append(this.e);
        sb.append(", top=");
        sb.append(this.f);
        sb.append(", bottom=");
        return android.support.v4.media.session.a.p(sb, this.g, ')');
    }
}
