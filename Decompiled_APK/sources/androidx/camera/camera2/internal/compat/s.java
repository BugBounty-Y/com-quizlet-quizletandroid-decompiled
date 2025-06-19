package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;

/* loaded from: classes.dex */
public class s extends r {
    @Override // androidx.camera.camera2.internal.compat.r, androidx.compose.foundation.text.input.internal.u
    public final CameraCharacteristics f(String str) throws CameraAccessExceptionCompat {
        try {
            return ((CameraManager) this.b).getCameraCharacteristics(str);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }

    @Override // androidx.camera.camera2.internal.compat.r, androidx.compose.foundation.text.input.internal.u
    public final void n(String str, androidx.camera.core.impl.utils.executor.k kVar, CameraDevice.StateCallback stateCallback) throws CameraAccessException, CameraAccessExceptionCompat {
        try {
            ((CameraManager) this.b).openCamera(str, kVar, stateCallback);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }
}
