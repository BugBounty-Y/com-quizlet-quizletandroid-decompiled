package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import androidx.camera.core.impl.AbstractC0171j;

/* loaded from: classes.dex */
public final class P extends AbstractC0171j {
    public final CameraCaptureSession.CaptureCallback a;

    public P(CameraCaptureSession.CaptureCallback captureCallback) {
        if (captureCallback == null) {
            throw new NullPointerException("captureCallback is null");
        }
        this.a = captureCallback;
    }
}
