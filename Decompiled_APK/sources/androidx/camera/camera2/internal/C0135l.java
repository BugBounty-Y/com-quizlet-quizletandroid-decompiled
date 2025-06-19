package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.view.Surface;
import androidx.activity.RunnableC0043o;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* renamed from: androidx.camera.camera2.internal.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0135l extends CameraCaptureSession.CaptureCallback {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;

    public C0135l(int i) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = Y5.b(new C0132i(this, 3));
                break;
            default:
                this.c = null;
                this.b = new HashMap();
                break;
        }
    }

    public void a(CaptureRequest captureRequest, List list) {
        HashMap map = (HashMap) this.b;
        List list2 = (List) map.get(captureRequest);
        if (list2 == null) {
            map.put(captureRequest, list);
            return;
        }
        ArrayList arrayList = new ArrayList(list2.size() + list.size());
        arrayList.addAll(list);
        arrayList.addAll(list2);
        map.put(captureRequest, arrayList);
    }

    public void b() {
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.c;
        if (iVar != null) {
            iVar.b(null);
            this.c = null;
        }
    }

    public List c(CaptureRequest captureRequest) {
        List list = (List) ((HashMap) this.b).get(captureRequest);
        return list != null ? list : Collections.EMPTY_LIST;
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureBufferLost(final CameraCaptureSession cameraCaptureSession, final CaptureRequest captureRequest, final Surface surface, final long j) {
        switch (this.a) {
            case 1:
                Iterator it2 = c(captureRequest).iterator();
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
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new Runnable() { // from class: androidx.camera.camera2.internal.compat.d
                    @Override // java.lang.Runnable
                    public final void run() {
                        ((CameraCaptureSession.CaptureCallback) this.a.b).onCaptureBufferLost(cameraCaptureSession, captureRequest, surface, j);
                    }
                });
                break;
            default:
                super.onCaptureBufferLost(cameraCaptureSession, captureRequest, surface, j);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public final void onCaptureCompleted(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, TotalCaptureResult totalCaptureResult) {
        switch (this.a) {
            case 0:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.activity.r(4, this, totalCaptureResult));
                break;
            case 1:
                Iterator it2 = c(captureRequest).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureCompleted(cameraCaptureSession, captureRequest, totalCaptureResult);
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.camera.camera2.internal.compat.b(this, cameraCaptureSession, captureRequest, totalCaptureResult, 0));
                break;
            default:
                b();
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureFailed(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, CaptureFailure captureFailure) {
        switch (this.a) {
            case 1:
                Iterator it2 = c(captureRequest).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureFailed(cameraCaptureSession, captureRequest, captureFailure);
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.camera.camera2.internal.compat.b(this, cameraCaptureSession, captureRequest, captureFailure, 2));
                break;
            case 3:
                b();
                break;
            default:
                super.onCaptureFailed(cameraCaptureSession, captureRequest, captureFailure);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureProgressed(CameraCaptureSession cameraCaptureSession, CaptureRequest captureRequest, CaptureResult captureResult) {
        switch (this.a) {
            case 1:
                Iterator it2 = c(captureRequest).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureProgressed(cameraCaptureSession, captureRequest, captureResult);
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new androidx.camera.camera2.internal.compat.b(this, cameraCaptureSession, captureRequest, captureResult, 1));
                break;
            default:
                super.onCaptureProgressed(cameraCaptureSession, captureRequest, captureResult);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureSequenceAborted(CameraCaptureSession cameraCaptureSession, int i) {
        switch (this.a) {
            case 1:
                Iterator it2 = ((HashMap) this.b).values().iterator();
                while (it2.hasNext()) {
                    Iterator it3 = ((List) it2.next()).iterator();
                    while (it3.hasNext()) {
                        ((CameraCaptureSession.CaptureCallback) it3.next()).onCaptureSequenceAborted(cameraCaptureSession, i);
                    }
                }
                S s = (S) this.c;
                if (s != null) {
                    s.a();
                    break;
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new RunnableC0043o(this, cameraCaptureSession, i, 4));
                break;
            case 3:
                b();
                break;
            default:
                super.onCaptureSequenceAborted(cameraCaptureSession, i);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureSequenceCompleted(final CameraCaptureSession cameraCaptureSession, final int i, final long j) {
        switch (this.a) {
            case 1:
                Iterator it2 = ((HashMap) this.b).values().iterator();
                while (it2.hasNext()) {
                    Iterator it3 = ((List) it2.next()).iterator();
                    while (it3.hasNext()) {
                        ((CameraCaptureSession.CaptureCallback) it3.next()).onCaptureSequenceCompleted(cameraCaptureSession, i, j);
                    }
                }
                S s = (S) this.c;
                if (s != null) {
                    s.a();
                    break;
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new Runnable() { // from class: androidx.camera.camera2.internal.compat.c
                    @Override // java.lang.Runnable
                    public final void run() {
                        ((CameraCaptureSession.CaptureCallback) this.a.b).onCaptureSequenceCompleted(cameraCaptureSession, i, j);
                    }
                });
                break;
            case 3:
                b();
                break;
            default:
                super.onCaptureSequenceCompleted(cameraCaptureSession, i, j);
                break;
        }
    }

    @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
    public void onCaptureStarted(final CameraCaptureSession cameraCaptureSession, final CaptureRequest captureRequest, final long j, final long j2) {
        switch (this.a) {
            case 1:
                Iterator it2 = c(captureRequest).iterator();
                while (it2.hasNext()) {
                    ((CameraCaptureSession.CaptureCallback) it2.next()).onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                }
                break;
            case 2:
                ((androidx.camera.core.impl.utils.executor.k) this.c).execute(new Runnable() { // from class: androidx.camera.camera2.internal.compat.a
                    @Override // java.lang.Runnable
                    public final void run() {
                        ((CameraCaptureSession.CaptureCallback) this.a.b).onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                    }
                });
                break;
            case 3:
                b();
                break;
            default:
                super.onCaptureStarted(cameraCaptureSession, captureRequest, j, j2);
                break;
        }
    }

    public C0135l(androidx.camera.core.impl.utils.executor.k kVar, CameraCaptureSession.CaptureCallback captureCallback) {
        this.a = 2;
        this.c = kVar;
        this.b = captureCallback;
    }

    public C0135l(androidx.camera.core.impl.utils.executor.k kVar) {
        this.a = 0;
        this.b = new HashSet();
        this.c = kVar;
    }
}
