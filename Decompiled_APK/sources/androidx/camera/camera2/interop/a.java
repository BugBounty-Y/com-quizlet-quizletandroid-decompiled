package androidx.camera.camera2.interop;

import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.camera2.internal.C0137n;
import androidx.camera.core.CameraControl$OperationCanceledException;
import androidx.camera.core.impl.utils.executor.k;
import androidx.concurrent.futures.i;
import androidx.concurrent.futures.j;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ a(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // androidx.concurrent.futures.j
    public final Object d(final i iVar) {
        switch (this.a) {
            case 0:
                final c cVar = this.b;
                cVar.getClass();
                final int i = 1;
                ((k) cVar.e).execute(new Runnable() { // from class: androidx.camera.camera2.interop.b
                    @Override // java.lang.Runnable
                    public final void run() {
                        switch (i) {
                            case 0:
                                i iVar2 = iVar;
                                c cVar2 = cVar;
                                cVar2.c = true;
                                CameraControl$OperationCanceledException cameraControl$OperationCanceledException = new CameraControl$OperationCanceledException("Camera2CameraControl was updated with new options.");
                                i iVar3 = (i) cVar2.g;
                                if (iVar3 != null) {
                                    iVar3.d(cameraControl$OperationCanceledException);
                                    cVar2.g = null;
                                }
                                cVar2.g = iVar2;
                                if (cVar2.b) {
                                    C0137n c0137n = (C0137n) cVar2.d;
                                    c0137n.getClass();
                                    androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(c0137n, 0))).a(new RunnableC0041m(cVar2, 8), (k) cVar2.e);
                                    cVar2.c = false;
                                    break;
                                }
                                break;
                            default:
                                i iVar4 = iVar;
                                c cVar3 = cVar;
                                cVar3.c = true;
                                CameraControl$OperationCanceledException cameraControl$OperationCanceledException2 = new CameraControl$OperationCanceledException("Camera2CameraControl was updated with new options.");
                                i iVar5 = (i) cVar3.g;
                                if (iVar5 != null) {
                                    iVar5.d(cameraControl$OperationCanceledException2);
                                    cVar3.g = null;
                                }
                                cVar3.g = iVar4;
                                if (cVar3.b) {
                                    C0137n c0137n2 = (C0137n) cVar3.d;
                                    c0137n2.getClass();
                                    androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(c0137n2, 0))).a(new RunnableC0041m(cVar3, 8), (k) cVar3.e);
                                    cVar3.c = false;
                                    break;
                                }
                                break;
                        }
                    }
                });
                return "addCaptureRequestOptions";
            default:
                final c cVar2 = this.b;
                cVar2.getClass();
                final int i2 = 0;
                ((k) cVar2.e).execute(new Runnable() { // from class: androidx.camera.camera2.interop.b
                    @Override // java.lang.Runnable
                    public final void run() {
                        switch (i2) {
                            case 0:
                                i iVar2 = iVar;
                                c cVar22 = cVar2;
                                cVar22.c = true;
                                CameraControl$OperationCanceledException cameraControl$OperationCanceledException = new CameraControl$OperationCanceledException("Camera2CameraControl was updated with new options.");
                                i iVar3 = (i) cVar22.g;
                                if (iVar3 != null) {
                                    iVar3.d(cameraControl$OperationCanceledException);
                                    cVar22.g = null;
                                }
                                cVar22.g = iVar2;
                                if (cVar22.b) {
                                    C0137n c0137n = (C0137n) cVar22.d;
                                    c0137n.getClass();
                                    androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(c0137n, 0))).a(new RunnableC0041m(cVar22, 8), (k) cVar22.e);
                                    cVar22.c = false;
                                    break;
                                }
                                break;
                            default:
                                i iVar4 = iVar;
                                c cVar3 = cVar2;
                                cVar3.c = true;
                                CameraControl$OperationCanceledException cameraControl$OperationCanceledException2 = new CameraControl$OperationCanceledException("Camera2CameraControl was updated with new options.");
                                i iVar5 = (i) cVar3.g;
                                if (iVar5 != null) {
                                    iVar5.d(cameraControl$OperationCanceledException2);
                                    cVar3.g = null;
                                }
                                cVar3.g = iVar4;
                                if (cVar3.b) {
                                    C0137n c0137n2 = (C0137n) cVar3.d;
                                    c0137n2.getClass();
                                    androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(c0137n2, 0))).a(new RunnableC0041m(cVar3, 8), (k) cVar3.e);
                                    cVar3.c = false;
                                    break;
                                }
                                break;
                        }
                    }
                });
                return "clearCaptureRequestOptions";
        }
    }
}
