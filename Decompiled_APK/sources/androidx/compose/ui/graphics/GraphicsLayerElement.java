package androidx.compose.ui.graphics;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.node.AbstractC0910f;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class GraphicsLayerElement extends androidx.compose.ui.node.T {
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final float f;
    public final long g;
    public final V h;
    public final boolean i;
    public final long j;
    public final long k;
    public final int l;

    public GraphicsLayerElement(float f, float f2, float f3, float f4, float f5, long j, V v, boolean z, long j2, long j3, int i) {
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        this.f = f5;
        this.g = j;
        this.h = v;
        this.i = z;
        this.j = j2;
        this.k = j3;
        this.l = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GraphicsLayerElement)) {
            return false;
        }
        GraphicsLayerElement graphicsLayerElement = (GraphicsLayerElement) obj;
        return Float.compare(this.b, graphicsLayerElement.b) == 0 && Float.compare(this.c, graphicsLayerElement.c) == 0 && Float.compare(this.d, graphicsLayerElement.d) == 0 && Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0 && Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0 && Float.compare(this.e, graphicsLayerElement.e) == 0 && Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0 && Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0 && Float.compare(this.f, graphicsLayerElement.f) == 0 && Float.compare(8.0f, 8.0f) == 0 && Z.a(this.g, graphicsLayerElement.g) && Intrinsics.b(this.h, graphicsLayerElement.h) && this.i == graphicsLayerElement.i && C0861v.c(this.j, graphicsLayerElement.j) && C0861v.c(this.k, graphicsLayerElement.k) && this.l == graphicsLayerElement.l;
    }

    public final int hashCode() {
        int iB = android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.b) * 31, this.c, 31), this.d, 31), DefinitionKt.NO_Float_VALUE, 31), DefinitionKt.NO_Float_VALUE, 31), this.e, 31), DefinitionKt.NO_Float_VALUE, 31), DefinitionKt.NO_Float_VALUE, 31), this.f, 31), 8.0f, 31);
        int i = Z.c;
        int iG = d0.g((this.h.hashCode() + d0.d(iB, 31, this.g)) * 31, 961, this.i);
        int i2 = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Integer.hashCode(this.l) + d0.d(d0.d(iG, 31, this.j), 31, this.k);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        W w = new W();
        w.n = this.b;
        w.o = this.c;
        w.p = this.d;
        w.q = this.e;
        w.r = this.f;
        w.s = 8.0f;
        w.t = this.g;
        w.u = this.h;
        w.v = this.i;
        w.w = this.j;
        w.x = this.k;
        w.y = this.l;
        w.z = new C0775b0(w, 11);
        return w;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        W w = (W) pVar;
        w.n = this.b;
        w.o = this.c;
        w.p = this.d;
        w.q = this.e;
        w.r = this.f;
        w.s = 8.0f;
        w.t = this.g;
        w.u = this.h;
        w.v = this.i;
        w.w = this.j;
        w.x = this.k;
        w.y = this.l;
        androidx.compose.ui.node.a0 a0Var = AbstractC0910f.t(w, 2).m;
        if (a0Var != null) {
            a0Var.r1(w.z, true);
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GraphicsLayerElement(scaleX=");
        sb.append(this.b);
        sb.append(", scaleY=");
        sb.append(this.c);
        sb.append(", alpha=");
        sb.append(this.d);
        sb.append(", translationX=0.0, translationY=0.0, shadowElevation=");
        sb.append(this.e);
        sb.append(", rotationX=0.0, rotationY=0.0, rotationZ=");
        sb.append(this.f);
        sb.append(", cameraDistance=8.0, transformOrigin=");
        sb.append((Object) Z.d(this.g));
        sb.append(", shape=");
        sb.append(this.h);
        sb.append(", clip=");
        sb.append(this.i);
        sb.append(", renderEffect=null, ambientShadowColor=");
        d0.x(this.j, ", spotShadowColor=", sb);
        sb.append((Object) C0861v.i(this.k));
        sb.append(", compositingStrategy=");
        sb.append((Object) ("CompositingStrategy(value=" + this.l + ')'));
        sb.append(')');
        return sb.toString();
    }
}
