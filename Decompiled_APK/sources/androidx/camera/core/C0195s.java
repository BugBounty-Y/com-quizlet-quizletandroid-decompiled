package androidx.camera.core;

import android.os.Handler;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import java.util.concurrent.Executor;

/* renamed from: androidx.camera.core.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0195s implements androidx.camera.core.internal.k {
    public static final C0162c b = new C0162c("camerax.core.appConfig.cameraFactoryProvider", androidx.camera.camera2.a.class, null);
    public static final C0162c c = new C0162c("camerax.core.appConfig.deviceSurfaceManagerProvider", androidx.camera.camera2.b.class, null);
    public static final C0162c d = new C0162c("camerax.core.appConfig.useCaseConfigFactoryProvider", androidx.camera.camera2.c.class, null);
    public static final C0162c e = new C0162c("camerax.core.appConfig.cameraExecutor", Executor.class, null);
    public static final C0162c f = new C0162c("camerax.core.appConfig.schedulerHandler", Handler.class, null);
    public static final C0162c g = new C0162c("camerax.core.appConfig.minimumLoggingLevel", Integer.TYPE, null);
    public static final C0162c h = new C0162c("camerax.core.appConfig.availableCamerasLimiter", C0192o.class, null);
    public static final C0162c i = new C0162c("camerax.core.appConfig.cameraOpenRetryMaxTimeoutInMillisWhileResuming", Long.TYPE, null);
    public static final C0162c j = new C0162c("camerax.core.appConfig.cameraProviderInitRetryPolicy", Z.class, null);
    public static final C0162c k = new C0162c("camerax.core.appConfig.quirksSettings", androidx.camera.core.impl.f0.class, null);
    public final C0163c0 a;

    public C0195s(C0163c0 c0163c0) {
        this.a = c0163c0;
    }

    public final C0192o a() {
        Object objE;
        try {
            objE = this.a.e(h);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        return (C0192o) objE;
    }

    public final androidx.camera.camera2.a b() {
        Object objE;
        try {
            objE = this.a.e(b);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        return (androidx.camera.camera2.a) objE;
    }

    public final long k() {
        C0162c c0162c = i;
        Object objE = -1L;
        C0163c0 c0163c0 = this.a;
        c0163c0.getClass();
        try {
            objE = c0163c0.e(c0162c);
        } catch (IllegalArgumentException unused) {
        }
        return ((Long) objE).longValue();
    }

    public final androidx.camera.camera2.b l() {
        Object objE;
        try {
            objE = this.a.e(c);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        return (androidx.camera.camera2.b) objE;
    }

    public final androidx.camera.camera2.c m() {
        Object objE;
        try {
            objE = this.a.e(d);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        return (androidx.camera.camera2.c) objE;
    }

    @Override // androidx.camera.core.impl.j0
    public final androidx.camera.core.impl.H n() {
        return this.a;
    }
}
