package androidx.compose.animation;

import androidx.compose.animation.core.w0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.layout.InterfaceC0901w;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* renamed from: androidx.compose.animation.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0291s implements InterfaceC0901w {
    public final w0 b;
    public final InterfaceC0773a0 c;
    public final /* synthetic */ C0292t d;

    public C0291s(C0292t c0292t, w0 w0Var, InterfaceC0773a0 interfaceC0773a0) {
        this.d = c0292t;
        this.b = w0Var;
        this.c = interfaceC0773a0;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return j.z(i);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return j.x(i);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return j.X(i);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(j2);
        C0292t c0292t = this.d;
        long jA = m.a0() ? R5.a(wB.a, wB.b) : ((androidx.compose.ui.unit.j) this.b.a(new C0278e(1, c0292t, this), new androidx.camera.lifecycle.f(c0292t, 2)).getValue()).a;
        return m.n0((int) (jA >> 32), (int) (4294967295L & jA), kotlin.collections.V.c(), new r(c0292t, wB, jA));
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return j.b(i);
    }
}
