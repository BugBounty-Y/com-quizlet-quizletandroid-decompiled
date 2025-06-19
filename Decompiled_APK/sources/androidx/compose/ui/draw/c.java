package androidx.compose.ui.draw;

import androidx.compose.animation.core.C0242g;
import androidx.compose.animation.core.K;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.c0;
import androidx.compose.ui.p;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends p implements c0, b, InterfaceC0919o {
    public final d n;
    public boolean o;
    public k p;
    public Function1 q;

    public c(d dVar, Function1 function1) {
        this.n = dVar;
        this.q = function1;
        dVar.a = this;
        new K(this, 28);
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        k kVar = this.p;
        if (kVar != null) {
            kVar.c();
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void M() {
        M0();
    }

    public final void M0() {
        k kVar = this.p;
        if (kVar != null) {
            kVar.c();
        }
        this.o = false;
        this.n.b = null;
        AbstractC0910f.n(this);
    }

    @Override // androidx.compose.ui.draw.b
    public final androidx.compose.ui.unit.b a() {
        return AbstractC0910f.v(this).r;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        boolean z = this.o;
        d dVar = this.n;
        if (!z) {
            dVar.b = null;
            AbstractC0910f.s(this, new C0242g(18, this, dVar));
            if (dVar.b == null) {
                W4.g("DrawResult not defined, did you forget to call onDraw?");
                throw null;
            }
            this.o = true;
        }
        com.google.firebase.platforminfo.c cVar = dVar.b;
        Intrinsics.d(cVar);
        ((r) cVar.a).invoke(g);
    }

    @Override // androidx.compose.ui.draw.b
    public final long g() {
        return R5.f(AbstractC0910f.t(this, 128).c);
    }

    @Override // androidx.compose.ui.draw.b
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return AbstractC0910f.v(this).s;
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        M0();
    }
}
