package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public final class G0 implements InterfaceC0334k0 {
    public final /* synthetic */ L0 a;
    public final /* synthetic */ I0 b;

    public G0(L0 l0, I0 i0) {
        this.a = l0;
        this.b = i0;
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0334k0
    public final float a(float f) {
        L0 l0 = this.a;
        long jD = l0.d(l0.g(f));
        L0 l02 = this.b.a;
        l02.g = 2;
        androidx.compose.foundation.C0 c0 = l02.b;
        return l0.c(l0.f((c0 == null || !(l02.a.d() || l02.a.b())) ? L0.a(l02, l02.h, jD, 2) : c0.f(jD, l02.g, l02.j)));
    }
}
