package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.view.Surface;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.v0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class G extends CameraCaptureSession.CaptureCallback {
    public final /* synthetic */ int a;
    public final Object b;

    public G(AbstractC0171j abstractC0171j) {
        this.a = 1;
        if (abstractC0171j == null) {
            throw new NullPointerException("cameraCaptureCallback is null");
        }
        this.b = abstractC0171j;
    }

    public static int a(CaptureRequest captureRequest) {
        Integer num;
        if ((captureRequest.getTag() instanceof v0) && (num = (Integer) ((v0) captureRequest.getTag()).a.get("CAPTURE_CONFIG_ID_KEY")) != null) {
            return num.intValue();
        }
        return -1;
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureBufferLost(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, Surface surface, long j) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    CaptureRequest captureRequest2 = captureRequest;
                    Surface surface2 = surface;
                    long j2 = j;
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureBufferLost(cameraCaptureSession, captureRequest2, surface2, j2);
                    captureRequest = captureRequest2;
                    surface = surface2;
                    j = j2;
                }
                break;
            default:
                super.onCaptureBufferLost(cameraCaptureSession, captureRequest, surface, j);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public final void onCaptureCompleted(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, TotalCaptureResult totalCaptureResult) {
        v0 v0Var;
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureCompleted(cameraCaptureSession, captureRequest, totalCaptureResult);
                }
                return;
            case 1:
                super.onCaptureCompleted(cameraCaptureSession, captureRequest, totalCaptureResult);
                Object tag = captureRequest.getTag();
                if (tag != null) {
                    AbstractC3242q6.c("The tagBundle object from the CaptureResult is not a TagBundle object.", tag instanceof v0);
                    v0Var = (v0) tag;
                } else {
                    v0Var = v0.b;
                }
                ((AbstractC0171j) this.b).b(a(captureRequest), new androidx.work.impl.model.e(1, v0Var, totalCaptureResult));
                return;
            default:
                synchronized (((V) this.b).a) {
                    try {
                        androidx.camera.core.impl.q0 q0Var = ((V) this.b).f;
                        if (q0Var == null) {
                            return;
                        }
                        androidx.camera.core.impl.F f = q0Var.g;
                        AbstractC3053s1.f(3, "CaptureSession");
                        V v = (V) this.b;
                        v.n.getClass();
                        v.j(Collections.singletonList(androidx.camera.camera2.internal.compat.workaround.e.k(f)));
                        return;
                    } finally {
                    }
                }
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureFailed(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, CaptureFailure captureFailure) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureFailed(cameraCaptureSession, captureRequest, captureFailure);
                }
                break;
            case 1:
                super.onCaptureFailed(cameraCaptureSession, captureRequest, captureFailure);
                ((AbstractC0171j) this.b).c(a(captureRequest), new assistantMode.utils.studiableMetadata.b(2));
                break;
            default:
                super.onCaptureFailed(cameraCaptureSession, captureRequest, captureFailure);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureProgressed(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, CaptureResult captureResult) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureProgressed(cameraCaptureSession, captureRequest, captureResult);
                }
                break;
            default:
                super.onCaptureProgressed(cameraCaptureSession, captureRequest, captureResult);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureSequenceAborted(CameraCaptureSession cameraCaptureSession, int i) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureSequenceAborted(cameraCaptureSession, i);
                }
                break;
            default:
                super.onCaptureSequenceAborted(cameraCaptureSession, i);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureSequenceCompleted(CameraCaptureSession cameraCaptureSession, int i, long j) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureSequenceCompleted(cameraCaptureSession, i, j);
                }
                break;
            default:
                super.onCaptureSequenceCompleted(cameraCaptureSession, i, j);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureStarted(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, long j, long j2) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                }
                break;
            case 1:
                super.onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                ((AbstractC0171j) this.b).d(a(captureRequest));
                break;
            default:
                super.onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                break;
        }
    }

    public G(List list) {
        this.a = 0;
        this.b = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            CameraCaptureSession.CaptureCallback captureCallback = (CameraCaptureSession.CaptureCallback) it2.next();
            if (!(captureCallback instanceof H)) {
                ((ArrayList) this.b).add(captureCallback);
            }
        }
    }

    public G(V v) {
        this.a = 2;
        this.b = v;
    }
}
