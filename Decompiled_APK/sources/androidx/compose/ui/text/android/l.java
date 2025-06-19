package androidx.compose.ui.text.android;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class l {
    public final int a;
    public final int b;
    public final boolean c;

    public l(int i, int i2, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return this.a == lVar.a && this.b == lVar.b && this.c == lVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BidiRun(start=");
        sb.append(this.a);
        sb.append(", end=");
        sb.append(this.b);
        sb.append(", isRtl=");
        return android.support.v4.media.session.a.u(sb, this.c, ')');
    }
}
