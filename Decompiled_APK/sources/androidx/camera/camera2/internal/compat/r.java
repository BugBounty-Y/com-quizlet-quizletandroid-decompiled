package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.os.Build;
import androidx.camera.camera2.internal.C0145w;
import androidx.compose.foundation.text.input.internal.u;

/* loaded from: classes.dex */
public class r extends u {
    public static boolean v(RuntimeException runtimeException) {
        StackTraceElement[] stackTrace;
        if (Build.VERSION.SDK_INT == 28) {
            if ((!runtimeException.getClass().equals(RuntimeException.class) || (stackTrace = runtimeException.getStackTrace()) == null || stackTrace.length < 0) ? false : "_enableShutterSound".equals(stackTrace[0].getMethodName())) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.compose.foundation.text.input.internal.u
    public CameraCharacteristics f(String str) throws CameraAccessExceptionCompat {
        try {
            return super.f(str);
        } catch (RuntimeException e) {
            if (v(e)) {
                throw new CameraAccessExceptionCompat(e);
            }
            throw e;
        }
    }

    @Override // androidx.compose.foundation.text.input.internal.u
    public void n(String str, androidx.camera.core.impl.utils.executor.k kVar, CameraDevice.StateCallback stateCallback) throws CameraAccessException, CameraAccessExceptionCompat {
        try {
            ((CameraManager) this.b).openCamera(str, kVar, stateCallback);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        } catch (IllegalArgumentException e2) {
        } catch (SecurityException e3) {
            throw e3;
        } catch (RuntimeException e4) {
            if (!v(e4)) {
                throw e4;
            }
            throw new CameraAccessExceptionCompat(e4);
        }
    }

    @Override // androidx.compose.foundation.text.input.internal.u
    public final void p(androidx.camera.core.impl.utils.executor.k kVar, C0145w c0145w) {
        ((CameraManager) this.b).registerAvailabilityCallback(kVar, c0145w);
    }

    @Override // androidx.compose.foundation.text.input.internal.u
    public final void u(CameraManager.AvailabilityCallback availabilityCallback) {
        ((CameraManager) this.b).unregisterAvailabilityCallback(availabilityCallback);
    }
}
