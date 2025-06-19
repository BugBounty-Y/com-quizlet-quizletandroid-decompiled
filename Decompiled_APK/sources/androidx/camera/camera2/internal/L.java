package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import android.media.ImageWriter;
import android.view.Surface;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class L extends CameraCaptureSession.StateCallback {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ L(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a(CameraCaptureSession cameraCaptureSession) {
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public void onActive(CameraCaptureSession cameraCaptureSession) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onActive(cameraCaptureSession);
                }
                break;
            case 1:
                k0 k0Var = (k0) this.b;
                k0Var.k(cameraCaptureSession);
                k0Var.a(k0Var);
                break;
            default:
                super.onActive(cameraCaptureSession);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public void onCaptureQueueEmpty(CameraCaptureSession cameraCaptureSession) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onCaptureQueueEmpty(cameraCaptureSession);
                }
                break;
            case 1:
                k0 k0Var = (k0) this.b;
                k0Var.k(cameraCaptureSession);
                k0Var.b(k0Var);
                break;
            default:
                super.onCaptureQueueEmpty(cameraCaptureSession);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public void onClosed(CameraCaptureSession cameraCaptureSession) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onClosed(cameraCaptureSession);
                }
                break;
            case 1:
                k0 k0Var = (k0) this.b;
                k0Var.k(cameraCaptureSession);
                k0Var.c(k0Var);
                break;
            default:
                super.onClosed(cameraCaptureSession);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public final void onConfigureFailed(CameraCaptureSession cameraCaptureSession) {
        androidx.concurrent.futures.i iVar;
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onConfigureFailed(cameraCaptureSession);
                }
                return;
            case 1:
                try {
                    ((k0) this.b).k(cameraCaptureSession);
                    k0 k0Var = (k0) this.b;
                    k0Var.d(k0Var);
                    synchronized (((k0) this.b).a) {
                        AbstractC3242q6.g(((k0) this.b).i, "OpenCaptureSession completer should not null");
                        k0 k0Var2 = (k0) this.b;
                        iVar = k0Var2.i;
                        k0Var2.i = null;
                    }
                    iVar.d(new IllegalStateException("onConfigureFailed"));
                    return;
                } catch (Throwable th) {
                    synchronized (((k0) this.b).a) {
                        AbstractC3242q6.g(((k0) this.b).i, "OpenCaptureSession completer should not null");
                        k0 k0Var3 = (k0) this.b;
                        androidx.concurrent.futures.i iVar2 = k0Var3.i;
                        k0Var3.i = null;
                        iVar2.d(new IllegalStateException("onConfigureFailed"));
                        throw th;
                    }
                }
            default:
                return;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public final void onConfigured(CameraCaptureSession cameraCaptureSession) {
        androidx.concurrent.futures.i iVar;
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onConfigured(cameraCaptureSession);
                }
                return;
            case 1:
                try {
                    ((k0) this.b).k(cameraCaptureSession);
                    k0 k0Var = (k0) this.b;
                    k0Var.e(k0Var);
                    synchronized (((k0) this.b).a) {
                        AbstractC3242q6.g(((k0) this.b).i, "OpenCaptureSession completer should not null");
                        k0 k0Var2 = (k0) this.b;
                        iVar = k0Var2.i;
                        k0Var2.i = null;
                    }
                    iVar.b(null);
                    return;
                } catch (Throwable th) {
                    synchronized (((k0) this.b).a) {
                        AbstractC3242q6.g(((k0) this.b).i, "OpenCaptureSession completer should not null");
                        k0 k0Var3 = (k0) this.b;
                        androidx.concurrent.futures.i iVar2 = k0Var3.i;
                        k0Var3.i = null;
                        iVar2.b(null);
                        throw th;
                    }
                }
            default:
                Surface inputSurface = cameraCaptureSession.getInputSurface();
                if (inputSurface != null) {
                    ((t0) this.b).i = ImageWriter.newInstance(inputSurface, 1);
                    return;
                }
                return;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public void onReady(CameraCaptureSession cameraCaptureSession) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onReady(cameraCaptureSession);
                }
                break;
            case 1:
                k0 k0Var = (k0) this.b;
                k0Var.k(cameraCaptureSession);
                k0Var.f(k0Var);
                break;
            default:
                super.onReady(cameraCaptureSession);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
    public void onSurfacePrepared(CameraCaptureSession cameraCaptureSession, Surface surface) {
        switch (this.a) {
            case 0:
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.StateCallback) it2.next()).onSurfacePrepared(cameraCaptureSession, surface);
                }
                break;
            case 1:
                k0 k0Var = (k0) this.b;
                k0Var.k(cameraCaptureSession);
                k0Var.h(k0Var, surface);
                break;
            default:
                super.onSurfacePrepared(cameraCaptureSession, surface);
                break;
        }
    }

    public L(List list) {
        this.a = 0;
        this.b = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            CameraCaptureSession.StateCallback stateCallback = (CameraCaptureSession.StateCallback) it2.next();
            if (!(stateCallback instanceof M)) {
                ((ArrayList) this.b).add(stateCallback);
            }
        }
    }
}
