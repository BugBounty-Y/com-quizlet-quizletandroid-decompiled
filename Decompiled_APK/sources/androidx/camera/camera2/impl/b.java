package androidx.camera.camera2.impl;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CaptureRequest;
import androidx.appcompat.app.L;
import androidx.camera.core.impl.C0162c;

/* loaded from: classes.dex */
public final class b extends L {
    public static final C0162c c = new C0162c("camera2.captureRequest.templateType", Integer.TYPE, null);
    public static final C0162c d = new C0162c("camera2.cameraCaptureSession.streamUseCase", Long.TYPE, null);
    public static final C0162c e = new C0162c("camera2.cameraDevice.stateCallback", CameraDevice.StateCallback.class, null);
    public static final C0162c f = new C0162c("camera2.cameraCaptureSession.stateCallback", CameraCaptureSession.StateCallback.class, null);
    public static final C0162c g = new C0162c("camera2.cameraCaptureSession.captureCallback", CameraCaptureSession.CaptureCallback.class, null);
    public static final C0162c h = new C0162c("camera2.cameraCaptureSession.physicalCameraId", String.class, null);

    public static C0162c U(CaptureRequest.Key key) {
        return new C0162c("camera2.captureRequest.option." + key.getName(), Object.class, key);
    }
}
