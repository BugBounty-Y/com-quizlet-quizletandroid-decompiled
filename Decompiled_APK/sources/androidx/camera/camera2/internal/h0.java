package androidx.camera.camera2.internal;

import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.LinkedHashSet;
import java.util.Objects;

/* loaded from: classes.dex */
public final /* synthetic */ class h0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ k0 b;
    public final /* synthetic */ k0 c;

    public /* synthetic */ h0(k0 k0Var, k0 k0Var2, int i) {
        this.a = i;
        this.b = k0Var;
        this.c = k0Var2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                k0 k0Var = this.b;
                k0 k0Var2 = this.c;
                c0 c0Var = k0Var.b;
                synchronized (c0Var.c) {
                    ((LinkedHashSet) c0Var.d).remove(k0Var);
                    ((LinkedHashSet) c0Var.e).remove(k0Var);
                }
                k0Var.g(k0Var2);
                if (k0Var.g != null) {
                    Objects.requireNonNull(k0Var.f);
                    k0Var.f.c(k0Var2);
                    return;
                } else {
                    AbstractC3053s1.h("SyncCaptureSessionBase", "[" + k0Var + "] Cannot call onClosed() when the CameraCaptureSession is not correctly configured.");
                    return;
                }
            default:
                k0 k0Var3 = this.b;
                Objects.requireNonNull(k0Var3.f);
                k0Var3.f.g(this.c);
                return;
        }
    }
}
