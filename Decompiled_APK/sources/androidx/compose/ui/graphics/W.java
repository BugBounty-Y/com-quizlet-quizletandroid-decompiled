package androidx.compose.ui.graphics;

import androidx.compose.animation.d0;
import androidx.compose.foundation.text.selection.n0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.node.InterfaceC0926w;

/* loaded from: classes.dex */
public final class W extends androidx.compose.ui.p implements InterfaceC0926w {
    public float n;
    public float o;
    public float p;
    public float q;
    public float r;
    public float s;
    public long t;
    public V u;
    public boolean v;
    public long w;
    public long x;
    public int y;
    public C0775b0 z;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(j2);
        return m.n0(wB.a, wB.b, kotlin.collections.V.c(), new n0(17, wB, this));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SimpleGraphicsLayerModifier(scaleX=");
        sb.append(this.n);
        sb.append(", scaleY=");
        sb.append(this.o);
        sb.append(", alpha = ");
        sb.append(this.p);
        sb.append(", translationX=0.0, translationY=0.0, shadowElevation=");
        sb.append(this.q);
        sb.append(", rotationX=0.0, rotationY=0.0, rotationZ=");
        sb.append(this.r);
        sb.append(", cameraDistance=");
        sb.append(this.s);
        sb.append(", transformOrigin=");
        sb.append((Object) Z.d(this.t));
        sb.append(", shape=");
        sb.append(this.u);
        sb.append(", clip=");
        sb.append(this.v);
        sb.append(", renderEffect=null, ambientShadowColor=");
        d0.x(this.w, ", spotShadowColor=", sb);
        d0.x(this.x, ", compositingStrategy=", sb);
        sb.append((Object) ("CompositingStrategy(value=" + this.y + ')'));
        sb.append(')');
        return sb.toString();
    }
}
