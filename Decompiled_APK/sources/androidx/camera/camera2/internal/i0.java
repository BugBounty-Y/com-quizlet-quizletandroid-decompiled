package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public final /* synthetic */ class i0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ k0 b;

    public /* synthetic */ i0(k0 k0Var, int i) {
        this.a = i;
        this.b = k0Var;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                k0 k0Var = this.b;
                k0Var.g(k0Var);
                return;
            default:
                k0 k0Var2 = this.b;
                k0.l();
                AbstractC3242q6.g(k0Var2.g, "Need to call openCaptureSession before using this API.");
                c0 c0Var = k0Var2.b;
                synchronized (c0Var.c) {
                    ((LinkedHashSet) c0Var.e).add(k0Var2);
                }
                ((CameraCaptureSession) ((com.quizlet.data.repository.searchexplanations.c) k0Var2.g.a).b).close();
                k0Var2.d.execute(new i0(k0Var2, 0));
                return;
        }
    }
}
