package androidx.camera.core;

import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class H extends D {
    public final Executor t;
    public final Object u = new Object();
    public O v;
    public G w;

    public H(Executor executor) {
        this.t = executor;
    }

    @Override // androidx.camera.core.D
    public final O a(androidx.camera.core.impl.S s) {
        return s.l();
    }

    @Override // androidx.camera.core.D
    public final void c() {
        synchronized (this.u) {
            try {
                O o = this.v;
                if (o != null) {
                    o.close();
                    this.v = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.D
    public final void f(O o) {
        synchronized (this.u) {
            try {
                if (!this.s) {
                    o.close();
                    return;
                }
                if (this.w != null) {
                    if (o.N().a() <= this.w.b.N().a()) {
                        o.close();
                    } else {
                        O o2 = this.v;
                        if (o2 != null) {
                            o2.close();
                        }
                        this.v = o;
                    }
                    return;
                }
                G g = new G(o, this);
                this.w = g;
                com.google.common.util.concurrent.e eVarB = b(g);
                com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(g, 6);
                eVarB.a(new androidx.camera.core.impl.utils.futures.h(0, eVarB, dVar), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
