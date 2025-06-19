package androidx.camera.core.impl;

/* loaded from: classes.dex */
public final class N implements A0, P, androidx.camera.core.internal.h {
    public static final C0162c b;
    public static final C0162c c;
    public static final C0162c d;
    public static final C0162c e;
    public static final C0162c f;
    public static final C0162c g;
    public static final C0162c h;
    public static final C0162c i;
    public static final C0162c j;
    public final C0163c0 a;

    static {
        Class cls = Integer.TYPE;
        b = new C0162c("camerax.core.imageCapture.captureMode", cls, null);
        c = new C0162c("camerax.core.imageCapture.flashMode", cls, null);
        d = new C0162c("camerax.core.imageCapture.bufferFormat", Integer.class, null);
        e = new C0162c("camerax.core.imageCapture.outputFormat", Integer.class, null);
        f = new C0162c("camerax.core.imageCapture.imageReaderProxyProvider", androidx.camera.core.P.class, null);
        g = new C0162c("camerax.core.imageCapture.useSoftwareJpegEncoder", Boolean.TYPE, null);
        h = new C0162c("camerax.core.imageCapture.flashType", cls, null);
        i = new C0162c("camerax.core.imageCapture.screenFlash", androidx.camera.core.J.class, null);
        j = new C0162c("camerax.core.useCase.isPostviewEnabled", Boolean.class, null);
    }

    public N(C0163c0 c0163c0) {
        this.a = c0163c0;
    }

    @Override // androidx.camera.core.impl.j0
    public final H n() {
        return this.a;
    }

    @Override // androidx.camera.core.impl.O
    public final int o() {
        return ((Integer) e(O.b0)).intValue();
    }
}
