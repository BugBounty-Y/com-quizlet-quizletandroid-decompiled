package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraManager;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.C0145w;

/* loaded from: classes.dex */
public final class p extends CameraManager.AvailabilityCallback {
    public final androidx.camera.core.impl.utils.executor.k a;
    public final C0145w b;
    public final Object c = new Object();
    public boolean d = false;

    public p(androidx.camera.core.impl.utils.executor.k kVar, C0145w c0145w) {
        this.a = kVar;
        this.b = c0145w;
    }

    @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
    public final void onCameraAccessPrioritiesChanged() {
        synchronized (this.c) {
            try {
                if (!this.d) {
                    this.a.execute(new RunnableC0041m(this, 7));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
    public final void onCameraAvailable(String str) {
        synchronized (this.c) {
            try {
                if (!this.d) {
                    this.a.execute(new o(this, str, 0));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
    public final void onCameraUnavailable(String str) {
        synchronized (this.c) {
            try {
                if (!this.d) {
                    this.a.execute(new o(this, str, 1));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
