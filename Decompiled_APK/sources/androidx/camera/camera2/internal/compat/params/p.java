package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import java.util.List;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public interface p {
    Object a();

    void b(g gVar);

    g c();

    Executor d();

    int e();

    CameraCaptureSession.StateCallback f();

    List g();

    void h(CaptureRequest captureRequest);
}
