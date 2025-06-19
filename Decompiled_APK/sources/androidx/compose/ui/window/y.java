package androidx.compose.ui.window;

import androidx.compose.animation.d0;
import androidx.compose.runtime.B;

/* loaded from: classes.dex */
public final class y {
    public final int a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;

    public y(int i) {
        this((i & 1) == 0, (i & 2) != 0, (i & 4) != 0, 1, true, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return this.a == yVar.a && this.b == yVar.b && this.c == yVar.c && this.d == yVar.d && this.e == yVar.e && this.f == yVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.g(d0.g(d0.g(d0.g(this.a * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public y(boolean z, boolean z2, boolean z3, int i, boolean z4, boolean z5) {
        B b = l.a;
        int i2 = !z ? 262152 : 262144;
        i2 = i == 2 ? i2 | 8192 : i2;
        i2 = z4 ? i2 : i2 | com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        boolean z6 = i == 1;
        this.a = i2;
        this.b = z6;
        this.c = z2;
        this.d = z3;
        this.e = true;
        this.f = z5;
    }
}
