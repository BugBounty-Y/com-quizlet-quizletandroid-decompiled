package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraManager;
import java.util.Set;

/* loaded from: classes.dex */
public final class t extends s {
    @Override // androidx.compose.foundation.text.input.internal.u
    public final Set g() throws CameraAccessExceptionCompat {
        try {
            return ((CameraManager) this.b).getConcurrentCameraIds();
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }
}
