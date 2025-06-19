package androidx.glance.appwidget;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.appwidget.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1220x {
    public final u0 a;
    public final int b;
    public final androidx.glance.layout.a c;
    public final androidx.glance.layout.b d;

    public C1220x(u0 u0Var, int i, androidx.glance.layout.a aVar, androidx.glance.layout.b bVar) {
        this.a = u0Var;
        this.b = i;
        this.c = aVar;
        this.d = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1220x)) {
            return false;
        }
        C1220x c1220x = (C1220x) obj;
        return this.a == c1220x.a && this.b == c1220x.b && Intrinsics.b(this.c, c1220x.c) && Intrinsics.b(this.d, c1220x.d);
    }

    public final int hashCode() {
        int iB = androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
        androidx.glance.layout.a aVar = this.c;
        int iHashCode = (iB + (aVar == null ? 0 : Integer.hashCode(aVar.a))) * 31;
        androidx.glance.layout.b bVar = this.d;
        return iHashCode + (bVar != null ? Integer.hashCode(bVar.a) : 0);
    }

    public final String toString() {
        return "ContainerSelector(type=" + this.a + ", numChildren=" + this.b + ", horizontalAlignment=" + this.c + ", verticalAlignment=" + this.d + ')';
    }

    public /* synthetic */ C1220x(u0 u0Var, int i, androidx.glance.layout.a aVar, androidx.glance.layout.b bVar, int i2) {
        this(u0Var, i, (i2 & 4) != 0 ? null : aVar, (i2 & 8) != 0 ? null : bVar);
    }
}
