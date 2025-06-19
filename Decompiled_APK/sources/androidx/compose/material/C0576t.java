package androidx.compose.material;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.C0861v;

/* renamed from: androidx.compose.material.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0576t {
    public final InterfaceC0773a0 a;
    public final InterfaceC0773a0 b;
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final InterfaceC0773a0 f;
    public final InterfaceC0773a0 g;
    public final InterfaceC0773a0 h;
    public final InterfaceC0773a0 i;
    public final InterfaceC0773a0 j;
    public final InterfaceC0773a0 k;
    public final InterfaceC0773a0 l;
    public final InterfaceC0773a0 m;

    public C0576t(long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8, long j9, long j10, long j11, long j12) {
        C0861v c0861v = new C0861v(j);
        androidx.compose.runtime.V v = androidx.compose.runtime.V.f;
        this.a = C0776c.y(c0861v, v);
        this.b = C0776c.y(new C0861v(j2), v);
        this.c = C0776c.y(new C0861v(j3), v);
        this.d = C0776c.y(new C0861v(j4), v);
        this.e = C0776c.y(new C0861v(j5), v);
        this.f = C0776c.y(new C0861v(j6), v);
        this.g = C0776c.y(new C0861v(j7), v);
        this.h = C0776c.y(new C0861v(j8), v);
        this.i = C0776c.y(new C0861v(j9), v);
        this.j = C0776c.y(new C0861v(j10), v);
        this.k = C0776c.y(new C0861v(j11), v);
        this.l = C0776c.y(new C0861v(j12), v);
        this.m = C0776c.y(Boolean.TRUE, v);
    }

    public final long a() {
        return ((C0861v) ((L0) this.f).getValue()).a;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Colors(primary=");
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.a).getValue()).a, ", primaryVariant=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.b).getValue()).a, ", secondary=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.c).getValue()).a, ", secondaryVariant=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.d).getValue()).a, ", background=", sb);
        sb.append((Object) C0861v.i(((C0861v) ((L0) this.e).getValue()).a));
        sb.append(", surface=");
        sb.append((Object) C0861v.i(a()));
        sb.append(", error=");
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.g).getValue()).a, ", onPrimary=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.h).getValue()).a, ", onSecondary=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.i).getValue()).a, ", onBackground=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.j).getValue()).a, ", onSurface=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.k).getValue()).a, ", onError=", sb);
        androidx.compose.animation.d0.x(((C0861v) ((L0) this.l).getValue()).a, ", isLight=", sb);
        sb.append(((Boolean) ((L0) this.m).getValue()).booleanValue());
        sb.append(')');
        return sb.toString();
    }
}
