package coil3.decode;

import com.google.android.gms.internal.mlkit_vision_camera.t3;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.InterfaceC5093j;

/* loaded from: classes.dex */
public final class s implements q {
    public final okio.n a;
    public final t3 b;
    public final Object c = new Object();
    public boolean d;
    public final InterfaceC5093j e;

    public s(InterfaceC5093j interfaceC5093j, okio.n nVar, t3 t3Var) {
        this.a = nVar;
        this.b = t3Var;
        this.e = interfaceC5093j;
    }

    @Override // coil3.decode.q
    public final okio.n V() {
        return this.a;
    }

    @Override // coil3.decode.q
    public final okio.x W() {
        synchronized (this.c) {
            if (this.d) {
                throw new IllegalStateException("closed");
            }
        }
        return null;
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        synchronized (this.c) {
            this.d = true;
            InterfaceC5093j interfaceC5093j = this.e;
            if (interfaceC5093j != null) {
                try {
                    interfaceC5093j.close();
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception unused) {
                }
            }
            Unit unit = Unit.a;
        }
    }

    @Override // coil3.decode.q
    public final InterfaceC5093j f0() {
        InterfaceC5093j interfaceC5093j;
        synchronized (this.c) {
            try {
                if (this.d) {
                    throw new IllegalStateException("closed");
                }
                interfaceC5093j = this.e;
                if (interfaceC5093j == null) {
                    okio.n nVar = this.a;
                    Intrinsics.d(null);
                    nVar.P(null);
                    throw null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return interfaceC5093j;
    }

    @Override // coil3.decode.q
    public final t3 getMetadata() {
        return this.b;
    }
}
