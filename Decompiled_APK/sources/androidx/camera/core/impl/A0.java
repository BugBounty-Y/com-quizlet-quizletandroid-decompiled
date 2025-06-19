package androidx.camera.core.impl;

import android.util.Range;

/* loaded from: classes.dex */
public interface A0 extends androidx.camera.core.internal.k, O {
    public static final C0162c n0 = new C0162c("camerax.core.useCase.defaultSessionConfig", q0.class, null);
    public static final C0162c o0 = new C0162c("camerax.core.useCase.defaultCaptureConfig", F.class, null);
    public static final C0162c p0 = new C0162c("camerax.core.useCase.sessionConfigUnpacker", androidx.camera.camera2.internal.J.class, null);
    public static final C0162c q0 = new C0162c("camerax.core.useCase.captureConfigUnpacker", androidx.camera.camera2.internal.I.class, null);
    public static final C0162c r0;
    public static final C0162c s0;
    public static final C0162c t0;
    public static final C0162c u0;
    public static final C0162c v0;
    public static final C0162c w0;
    public static final C0162c x0;

    static {
        Class cls = Integer.TYPE;
        r0 = new C0162c("camerax.core.useCase.surfaceOccupancyPriority", cls, null);
        s0 = new C0162c("camerax.core.useCase.targetFrameRate", Range.class, null);
        Class cls2 = Boolean.TYPE;
        t0 = new C0162c("camerax.core.useCase.zslDisabled", cls2, null);
        u0 = new C0162c("camerax.core.useCase.highResolutionDisabled", cls2, null);
        v0 = new C0162c("camerax.core.useCase.captureType", C0.class, null);
        w0 = new C0162c("camerax.core.useCase.previewStabilizationMode", cls, null);
        x0 = new C0162c("camerax.core.useCase.videoStabilizationMode", cls, null);
    }

    default int A() {
        return ((Integer) j(w0, 0)).intValue();
    }

    default C0 x() {
        return (C0) e(v0);
    }
}
