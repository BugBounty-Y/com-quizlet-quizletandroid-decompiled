package coil3.decode;

import com.google.android.gms.internal.mlkit_vision_camera.t3;
import okio.A;
import okio.AbstractC5085b;
import okio.InterfaceC5093j;

/* loaded from: classes.dex */
public final class p implements q {
    public final okio.x a;
    public final okio.n b;
    public final String c;
    public final AutoCloseable d;
    public final Object e = new Object();
    public boolean f;
    public A g;

    public p(okio.x xVar, okio.n nVar, String str, AutoCloseable autoCloseable) {
        this.a = xVar;
        this.b = nVar;
        this.c = str;
        this.d = autoCloseable;
    }

    @Override // coil3.decode.q
    public final okio.n V() {
        return this.b;
    }

    @Override // coil3.decode.q
    public final okio.x W() {
        okio.x xVar;
        synchronized (this.e) {
            if (this.f) {
                throw new IllegalStateException("closed");
            }
            xVar = this.a;
        }
        return xVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0014 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // java.lang.AutoCloseable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void close() {
        /*
            r2 = this;
            java.lang.Object r0 = r2.e
            monitor-enter(r0)
            r1 = 1
            r2.f = r1     // Catch: java.lang.Throwable -> L1e
            okio.A r1 = r2.g     // Catch: java.lang.Throwable -> L1e
            if (r1 == 0) goto L10
            r1.close()     // Catch: java.lang.RuntimeException -> Le java.lang.Exception -> L10 java.lang.Throwable -> L1e
            goto L10
        Le:
            r1 = move-exception
            throw r1     // Catch: java.lang.Throwable -> L1e
        L10:
            java.lang.AutoCloseable r1 = r2.d     // Catch: java.lang.Throwable -> L1e
            if (r1 == 0) goto L1a
            androidx.compose.ui.node.B.t(r1)     // Catch: java.lang.RuntimeException -> L18 java.lang.Exception -> L1a java.lang.Throwable -> L1e
            goto L1a
        L18:
            r1 = move-exception
            throw r1     // Catch: java.lang.Throwable -> L1e
        L1a:
            kotlin.Unit r1 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L1e
            monitor-exit(r0)
            return
        L1e:
            r1 = move-exception
            monitor-exit(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.decode.p.close():void");
    }

    @Override // coil3.decode.q
    public final InterfaceC5093j f0() {
        synchronized (this.e) {
            if (this.f) {
                throw new IllegalStateException("closed");
            }
            A a = this.g;
            if (a != null) {
                return a;
            }
            A aC = AbstractC5085b.c(this.b.P(this.a));
            this.g = aC;
            return aC;
        }
    }

    @Override // coil3.decode.q
    public final t3 getMetadata() {
        return null;
    }
}
