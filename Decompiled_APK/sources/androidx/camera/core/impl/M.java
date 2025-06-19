package androidx.camera.core.impl;

import androidx.camera.core.InterfaceC0200x;
import androidx.camera.core.InterfaceC0202z;

/* loaded from: classes.dex */
public final class M implements A0, P, androidx.camera.core.internal.l {
    public static final C0162c b = new C0162c("camerax.core.imageAnalysis.backpressureStrategy", InterfaceC0200x.class, null);
    public static final C0162c c = new C0162c("camerax.core.imageAnalysis.imageQueueDepth", Integer.TYPE, null);
    public static final C0162c d = new C0162c("camerax.core.imageAnalysis.imageReaderProxyProvider", androidx.camera.core.P.class, null);
    public static final C0162c e = new C0162c("camerax.core.imageAnalysis.outputImageFormat", InterfaceC0202z.class, null);
    public static final C0162c f = new C0162c("camerax.core.imageAnalysis.onePixelShiftEnabled", Boolean.class, null);
    public static final C0162c g = new C0162c("camerax.core.imageAnalysis.outputImageRotationEnabled", Boolean.class, null);
    public final C0163c0 a;

    public M(C0163c0 c0163c0) {
        this.a = c0163c0;
    }

    @Override // androidx.camera.core.impl.j0
    public final H n() {
        return this.a;
    }

    @Override // androidx.camera.core.impl.O
    public final int o() {
        return 35;
    }
}
