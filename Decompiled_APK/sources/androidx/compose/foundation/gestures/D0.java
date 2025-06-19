package androidx.compose.foundation.gestures;

import android.view.KeyEvent;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.C0276z;
import androidx.compose.ui.node.AbstractC0910f;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D0 extends Q implements androidx.compose.ui.node.c0, androidx.compose.ui.focus.n, androidx.compose.ui.input.key.d, androidx.compose.ui.node.n0 {
    public final C0336l0 A;
    public final C0343p B;
    public final L0 C;
    public final C0353u0 D;
    public final C0333k E;
    public C0313a F;
    public C0281h G;
    public C0 H;
    public androidx.compose.foundation.C0 x;
    public InterfaceC0314a0 y;
    public final androidx.compose.ui.input.nestedscroll.e z;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v2, types: [androidx.compose.foundation.gestures.a0] */
    /* JADX WARN: Type inference failed for: r8v0, types: [androidx.compose.foundation.gestures.D0, androidx.compose.ui.node.n, java.lang.Object] */
    public D0(androidx.compose.foundation.C0 c0, InterfaceC0319d interfaceC0319d, InterfaceC0314a0 interfaceC0314a0, EnumC0320d0 enumC0320d0, E0 e0, androidx.compose.foundation.interaction.l lVar, boolean z, boolean z2) {
        super(C0321e.e, z, lVar, enumC0320d0);
        this.x = c0;
        this.y = interfaceC0314a0;
        androidx.compose.ui.input.nestedscroll.e eVar = new androidx.compose.ui.input.nestedscroll.e();
        this.z = eVar;
        C0336l0 c0336l0 = new C0336l0();
        c0336l0.n = z;
        M0(c0336l0);
        this.A = c0336l0;
        C0343p c0343p = new C0343p(new C0276z(new androidx.appcompat.app.Q((androidx.compose.ui.unit.b) AbstractC0349s0.c)));
        this.B = c0343p;
        androidx.compose.foundation.C0 c02 = this.x;
        ?? r11 = this.y;
        L0 l0 = new L0(e0, c02, r11 == 0 ? c0343p : r11, enumC0320d0, z2, eVar);
        this.C = l0;
        C0353u0 c0353u0 = new C0353u0(l0, z);
        this.D = c0353u0;
        C0333k c0333k = new C0333k(enumC0320d0, l0, z2, interfaceC0319d);
        M0(c0333k);
        this.E = c0333k;
        M0(new androidx.compose.ui.input.nestedscroll.i(c0353u0, eVar));
        M0(new androidx.compose.ui.focus.t());
        androidx.compose.foundation.relocation.j jVar = new androidx.compose.foundation.relocation.j();
        jVar.n = c0333k;
        M0(jVar);
        androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f((Object) this, 12);
        androidx.compose.foundation.Z z3 = new androidx.compose.foundation.Z();
        z3.n = fVar;
        M0(z3);
    }

    @Override // androidx.compose.ui.input.key.d
    public final boolean B(KeyEvent keyEvent) {
        long jC;
        if (!this.r || ((!androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.b(keyEvent), androidx.compose.ui.input.key.a.m) && !androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.a(keyEvent.getKeyCode()), androidx.compose.ui.input.key.a.l)) || androidx.compose.ui.input.key.c.c(keyEvent) != 2 || keyEvent.isCtrlPressed())) {
            return false;
        }
        boolean z = this.C.d == EnumC0320d0.a;
        C0333k c0333k = this.E;
        if (z) {
            int i = (int) (c0333k.v & 4294967295L);
            jC = Q4.c(DefinitionKt.NO_Float_VALUE, androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.a(keyEvent.getKeyCode()), androidx.compose.ui.input.key.a.l) ? i : -i);
        } else {
            int i2 = (int) (c0333k.v >> 32);
            jC = Q4.c(androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.a(keyEvent.getKeyCode()), androidx.compose.ui.input.key.a.l) ? i2 : -i2, DefinitionKt.NO_Float_VALUE);
        }
        kotlinx.coroutines.E.A(A0(), null, null, new C0361y0(this, jC, null), 3);
        return true;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r5v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.gestures.Q, androidx.compose.ui.node.l0
    public final void E(androidx.compose.ui.input.pointer.f fVar, androidx.compose.ui.input.pointer.g gVar, long j) {
        long j2;
        ?? r0 = fVar.a;
        int size = r0.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                break;
            }
            if (((Boolean) this.q.invoke((androidx.compose.ui.input.pointer.n) r0.get(i))).booleanValue()) {
                super.E(fVar, gVar, j);
                break;
            }
            i++;
        }
        if (gVar == androidx.compose.ui.input.pointer.g.b && fVar.d == 6) {
            ?? r8 = fVar.a;
            int size2 = r8.size();
            for (int i2 = 0; i2 < size2; i2++) {
                if (((androidx.compose.ui.input.pointer.n) r8.get(i2)).b()) {
                    return;
                }
            }
            Intrinsics.d(this.F);
            androidx.compose.ui.unit.b bVar = AbstractC0910f.v(this).r;
            androidx.compose.ui.geometry.b bVar2 = new androidx.compose.ui.geometry.b(0L);
            int size3 = r8.size();
            int i3 = 0;
            while (true) {
                j2 = bVar2.a;
                if (i3 >= size3) {
                    break;
                }
                bVar2 = new androidx.compose.ui.geometry.b(androidx.compose.ui.geometry.b.h(j2, ((androidx.compose.ui.input.pointer.n) r8.get(i3)).j));
                i3++;
            }
            kotlinx.coroutines.E.A(A0(), null, null, new A0(this, androidx.compose.ui.geometry.b.i(j2, -bVar.c0(64)), null), 3);
            int size4 = r8.size();
            for (int i4 = 0; i4 < size4; i4++) {
                ((androidx.compose.ui.input.pointer.n) r8.get(i4)).a();
            }
        }
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        AbstractC0910f.s(this, new androidx.compose.animation.core.K(this, 5));
        this.F = C0313a.a;
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final Object T0(O o, P p) {
        androidx.compose.foundation.u0 u0Var = androidx.compose.foundation.u0.b;
        L0 l0 = this.C;
        Object objE = l0.e(u0Var, new C0355v0(o, l0, null), p);
        return objE == kotlin.coroutines.intrinsics.a.a ? objE : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final void U0(long j) {
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final void V0(long j) {
        kotlinx.coroutines.E.A(this.z.c(), null, null, new C0357w0(this, j, null), 3);
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final boolean W0() {
        L0 l0 = this.C;
        if (l0.a.a()) {
            return true;
        }
        androidx.compose.foundation.C0 c0 = l0.b;
        return c0 != null ? c0.d() : false;
    }

    @Override // androidx.compose.ui.input.key.d
    public final boolean k(KeyEvent keyEvent) {
        return false;
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        AbstractC0910f.s(this, new androidx.compose.animation.core.K(this, 5));
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        if (this.r && (this.G == null || this.H == null)) {
            this.G = new C0281h(this, 2);
            this.H = new C0(this, null);
        }
        C0281h c0281h = this.G;
        if (c0281h != null) {
            kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
            ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.j.d, new androidx.compose.ui.semantics.a(null, c0281h));
        }
        C0 c0 = this.H;
        if (c0 != null) {
            kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
            ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.j.e, c0);
        }
    }

    @Override // androidx.compose.ui.focus.n
    public final void z(androidx.compose.ui.focus.k kVar) {
        kVar.d(false);
    }
}
