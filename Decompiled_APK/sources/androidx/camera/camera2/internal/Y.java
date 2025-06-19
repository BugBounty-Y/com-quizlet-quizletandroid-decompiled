package androidx.camera.camera2.internal;

import android.hardware.camera2.CaptureRequest;
import androidx.camera.camera2.internal.compat.quirk.ImageCapturePixelHDRPlusQuirk;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;

/* loaded from: classes.dex */
public final class Y extends I {
    public static final Y b;

    static {
        new com.google.mlkit.common.internal.model.a(1);
        b = new Y();
    }

    @Override // androidx.camera.camera2.internal.I
    public final void a(androidx.camera.core.impl.N n, androidx.camera.core.a0 a0Var) {
        super.a(n, a0Var);
        if (n == null) {
            throw new IllegalArgumentException("config is not ImageCaptureConfig");
        }
        androidx.camera.core.impl.X xB = androidx.camera.core.impl.X.b();
        C0162c c0162c = androidx.camera.core.impl.N.b;
        if (n.c(c0162c)) {
            int iIntValue = ((Integer) n.e(c0162c)).intValue();
            if (((ImageCapturePixelHDRPlusQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ImageCapturePixelHDRPlusQuirk.class)) != null) {
                if (iIntValue == 0) {
                    CaptureRequest.Key key = CaptureRequest.CONTROL_ENABLE_ZSL;
                    xB.m(androidx.camera.camera2.impl.b.U(key), Boolean.TRUE);
                } else if (iIntValue == 1) {
                    CaptureRequest.Key key2 = CaptureRequest.CONTROL_ENABLE_ZSL;
                    xB.m(androidx.camera.camera2.impl.b.U(key2), Boolean.FALSE);
                }
            }
        }
        a0Var.d(new androidx.camera.camera2.impl.b(C0163c0.a(xB), 4));
    }
}
