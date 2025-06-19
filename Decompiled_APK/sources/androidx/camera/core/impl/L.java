package androidx.camera.core.impl;

import androidx.camera.camera2.internal.C0134k;
import java.util.List;

/* loaded from: classes.dex */
public abstract class L implements InterfaceC0183w {
    public final InterfaceC0183w a;

    public L(InterfaceC0183w interfaceC0183w) {
        this.a = interfaceC0183w;
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public int a() {
        return this.a.a();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final void b(androidx.camera.core.impl.utils.executor.a aVar, C0134k c0134k) {
        this.a.b(aVar, c0134k);
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public String c() {
        return this.a.c();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public InterfaceC0183w d() {
        return this.a.d();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final int e() {
        return this.a.e();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final String f() {
        return this.a.f();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public int g(int i) {
        return this.a.g(i);
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final i0 h() {
        return this.a.h();
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final List i(int i) {
        return this.a.i(i);
    }

    @Override // androidx.camera.core.impl.InterfaceC0183w
    public final void j(AbstractC0171j abstractC0171j) {
        this.a.j(abstractC0171j);
    }
}
