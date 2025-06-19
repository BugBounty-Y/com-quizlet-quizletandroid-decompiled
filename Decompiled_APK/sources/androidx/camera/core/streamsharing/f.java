package androidx.camera.core.streamsharing;

import androidx.camera.camera2.internal.s0;
import androidx.camera.core.impl.InterfaceC0161b0;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.l0;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class f implements InterfaceC0185y {
    public final InterfaceC0185y a;
    public final h b;
    public final i c;
    public final g d;

    public f(InterfaceC0185y interfaceC0185y, g gVar, s0 s0Var) {
        this.a = interfaceC0185y;
        this.d = gVar;
        this.b = new h(interfaceC0185y.g());
        this.c = new i(interfaceC0185y.n());
    }

    @Override // androidx.camera.core.k0
    public final void c(l0 l0Var) {
        S.d();
        this.d.c(l0Var);
    }

    @Override // androidx.camera.core.k0
    public final void d(l0 l0Var) {
        S.d();
        this.d.d(l0Var);
    }

    @Override // androidx.camera.core.k0
    public final void e(l0 l0Var) {
        S.d();
        this.d.e(l0Var);
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0161b0 f() {
        return this.a.f();
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0182v g() {
        return this.b;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void j(ArrayList arrayList) {
        throw new UnsupportedOperationException("Operation not supported by VirtualCamera.");
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final void k(ArrayList arrayList) {
        throw new UnsupportedOperationException("Operation not supported by VirtualCamera.");
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final boolean l() {
        return false;
    }

    @Override // androidx.camera.core.impl.InterfaceC0185y
    public final InterfaceC0183w n() {
        return this.c;
    }

    @Override // androidx.camera.core.k0
    public final void o(l0 l0Var) {
        S.d();
        this.d.o(l0Var);
    }
}
