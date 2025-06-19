package androidx.camera.core;

/* loaded from: classes.dex */
public final class E extends D {
    @Override // androidx.camera.core.D
    public final O a(androidx.camera.core.impl.S s) {
        return s.F();
    }

    @Override // androidx.camera.core.D
    public final void c() {
    }

    @Override // androidx.camera.core.D
    public final void f(O o) throws Throwable {
        com.google.common.util.concurrent.e eVarB = b(o);
        com.airbnb.lottie.network.c cVar = new com.airbnb.lottie.network.c(o, 6);
        eVarB.a(new androidx.camera.core.impl.utils.futures.h(0, eVarB, cVar), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
    }
}
