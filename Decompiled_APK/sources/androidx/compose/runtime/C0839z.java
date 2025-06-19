package androidx.compose.runtime;

/* renamed from: androidx.compose.runtime.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0839z implements InterfaceC0834w0 {
    public final kotlinx.coroutines.C a;

    public C0839z(kotlinx.coroutines.C c) {
        this.a = c;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        kotlinx.coroutines.C c = this.a;
        if (c instanceof C0838y0) {
            ((C0838y0) c).c();
        } else {
            kotlinx.coroutines.E.i(c, new J(1));
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        kotlinx.coroutines.C c = this.a;
        if (c instanceof C0838y0) {
            ((C0838y0) c).c();
        } else {
            kotlinx.coroutines.E.i(c, new J(1));
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
    }
}
