package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.params.SessionConfiguration;

/* loaded from: classes.dex */
public final class n extends m {
    @Override // androidx.camera.camera2.internal.compat.m
    public final void v(androidx.camera.camera2.internal.compat.params.q qVar) throws CameraAccessException, CameraAccessExceptionCompat {
        SessionConfiguration sessionConfiguration = (SessionConfiguration) qVar.a.a();
        sessionConfiguration.getClass();
        try {
            ((CameraDevice) this.b).createCaptureSession(sessionConfiguration);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }
}
