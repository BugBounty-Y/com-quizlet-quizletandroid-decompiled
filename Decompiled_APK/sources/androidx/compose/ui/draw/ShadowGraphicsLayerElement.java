package androidx.compose.ui.draw;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.C0855o;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.V;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.T;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.p;
import kotlin.C;
import kotlin.D;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ShadowGraphicsLayerElement extends T {
    public final float b;
    public final V c;
    public final boolean d;
    public final long e;
    public final long f;

    public ShadowGraphicsLayerElement(float f, V v, boolean z, long j, long j2) {
        this.b = f;
        this.c = v;
        this.d = z;
        this.e = j;
        this.f = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ShadowGraphicsLayerElement)) {
            return false;
        }
        ShadowGraphicsLayerElement shadowGraphicsLayerElement = (ShadowGraphicsLayerElement) obj;
        return androidx.compose.ui.unit.e.a(this.b, shadowGraphicsLayerElement.b) && Intrinsics.b(this.c, shadowGraphicsLayerElement.c) && this.d == shadowGraphicsLayerElement.d && C0861v.c(this.e, shadowGraphicsLayerElement.e) && C0861v.c(this.f, shadowGraphicsLayerElement.f);
    }

    public final int hashCode() {
        int iG = d0.g((this.c.hashCode() + (Float.hashCode(this.b) * 31)) * 31, 31, this.d);
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.f) + d0.d(iG, 31, this.e);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        return new C0855o(new C0775b0(this, 10));
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        C0855o c0855o = (C0855o) pVar;
        c0855o.n = new C0775b0(this, 10);
        a0 a0Var = AbstractC0910f.t(c0855o, 2).m;
        if (a0Var != null) {
            a0Var.r1(c0855o.n, true);
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShadowGraphicsLayerElement(elevation=");
        sb.append((Object) androidx.compose.ui.unit.e.b(this.b));
        sb.append(", shape=");
        sb.append(this.c);
        sb.append(", clip=");
        sb.append(this.d);
        sb.append(", ambientColor=");
        d0.x(this.e, ", spotColor=", sb);
        sb.append((Object) C0861v.i(this.f));
        sb.append(')');
        return sb.toString();
    }
}
