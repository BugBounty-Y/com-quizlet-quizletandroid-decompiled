package androidx.compose.ui.input.pointer;

import androidx.compose.animation.d0;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class p {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final boolean e;
    public final float f;
    public final int g;
    public final boolean h;
    public final ArrayList i;
    public final long j;
    public final long k;

    public p(long j, long j2, long j3, long j4, boolean z, float f, int i, boolean z2, ArrayList arrayList, long j5, long j6) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = z;
        this.f = f;
        this.g = i;
        this.h = z2;
        this.i = arrayList;
        this.j = j5;
        this.k = j6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return m.a(this.a, pVar.a) && this.b == pVar.b && androidx.compose.ui.geometry.b.b(this.c, pVar.c) && androidx.compose.ui.geometry.b.b(this.d, pVar.d) && this.e == pVar.e && Float.compare(this.f, pVar.f) == 0 && this.g == pVar.g && this.h == pVar.h && this.i.equals(pVar.i) && androidx.compose.ui.geometry.b.b(this.j, pVar.j) && androidx.compose.ui.geometry.b.b(this.k, pVar.k);
    }

    public final int hashCode() {
        return Long.hashCode(this.k) + d0.d(d0.h(this.i, d0.g(d0.b(this.g, android.support.v4.media.session.a.b(d0.g(d0.d(d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), this.f, 31), 31), 31, this.h), 31), 31, this.j);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PointerInputEventData(id=");
        sb.append((Object) m.b(this.a));
        sb.append(", uptime=");
        sb.append(this.b);
        sb.append(", positionOnScreen=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.c));
        sb.append(", position=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.d));
        sb.append(", down=");
        sb.append(this.e);
        sb.append(", pressure=");
        sb.append(this.f);
        sb.append(", type=");
        int i = this.g;
        sb.append((Object) (i != 1 ? i != 2 ? i != 3 ? i != 4 ? "Unknown" : "Eraser" : "Stylus" : "Mouse" : "Touch"));
        sb.append(", activeHover=");
        sb.append(this.h);
        sb.append(", historical=");
        sb.append(this.i);
        sb.append(", scrollDelta=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.j));
        sb.append(", originalEventPosition=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.k));
        sb.append(')');
        return sb.toString();
    }
}
