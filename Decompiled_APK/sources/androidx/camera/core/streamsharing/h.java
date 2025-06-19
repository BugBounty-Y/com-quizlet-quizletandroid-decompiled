package androidx.camera.core.streamsharing;

import android.graphics.Rect;
import androidx.camera.core.J;
import androidx.camera.core.impl.H;
import androidx.camera.core.impl.InterfaceC0182v;
import androidx.camera.core.impl.m0;

/* loaded from: classes.dex */
public final class h implements InterfaceC0182v {
    public final InterfaceC0182v b;

    public h(InterfaceC0182v interfaceC0182v) {
        this.b = interfaceC0182v;
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void a(H h) {
        this.b.a(h);
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final Rect b() {
        return this.b.b();
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void c(int i) {
        this.b.c(i);
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void d(m0 m0Var) {
        this.b.d(m0Var);
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final H e() {
        return this.b.e();
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void f(J j) {
        this.b.f(j);
    }

    @Override // androidx.camera.core.impl.InterfaceC0182v
    public final void g() {
        this.b.g();
    }
}
