package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class g extends com.quizlet.data.repository.searchexplanations.c {
    @Override // com.quizlet.data.repository.searchexplanations.c
    public final int c(ArrayList arrayList, androidx.camera.core.impl.utils.executor.k kVar, CameraCaptureSession.CaptureCallback captureCallback) {
        return ((CameraCaptureSession) this.b).captureBurstRequests(arrayList, kVar, captureCallback);
    }

    @Override // com.quizlet.data.repository.searchexplanations.c
    public final int o(CaptureRequest captureRequest, androidx.camera.core.impl.utils.executor.k kVar, CameraCaptureSession.CaptureCallback captureCallback) {
        return ((CameraCaptureSession) this.b).setSingleRepeatingRequest(captureRequest, kVar, captureCallback);
    }
}
