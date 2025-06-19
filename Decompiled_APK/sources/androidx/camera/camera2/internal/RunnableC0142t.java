package androidx.camera.camera2.internal;

import androidx.activity.RunnableC0041m;
import androidx.camera.core.CameraControl$OperationCanceledException;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.perimeterx.mobile_sdk.PerimeterXDelegate;

/* renamed from: androidx.camera.camera2.internal.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0142t implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    public /* synthetic */ RunnableC0142t(boolean z, int i, Object obj) {
        this.a = i;
        this.c = obj;
        this.b = z;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C c = (C) this.c;
                boolean z = this.b;
                c.C = z;
                if (z && c.H == 4) {
                    c.I(false);
                    break;
                }
                break;
            case 1:
                androidx.camera.camera2.interop.c cVar = (androidx.camera.camera2.interop.c) this.c;
                boolean z2 = cVar.b;
                boolean z3 = this.b;
                if (z2 != z3) {
                    cVar.b = z3;
                    if (!z3) {
                        CameraControl$OperationCanceledException cameraControl$OperationCanceledException = new CameraControl$OperationCanceledException("The camera control has became inactive.");
                        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) cVar.g;
                        if (iVar != null) {
                            iVar.d(cameraControl$OperationCanceledException);
                            cVar.g = null;
                            break;
                        }
                    } else if (cVar.c) {
                        C0137n c0137n = (C0137n) cVar.d;
                        c0137n.getClass();
                        androidx.camera.core.impl.utils.futures.i.d(Y5.b(new C0132i(c0137n, 0))).a(new RunnableC0041m(cVar, 8), (androidx.camera.core.impl.utils.executor.k) cVar.e);
                        cVar.c = false;
                        break;
                    }
                }
                break;
            default:
                boolean z4 = this.b;
                com.perimeterx.mobile_sdk.session.d dVar = (com.perimeterx.mobile_sdk.session.d) this.c;
                if (!z4) {
                    com.perimeterx.mobile_sdk.session.m mVar = dVar.b;
                    PerimeterXDelegate perimeterXDelegate = mVar.c;
                    if (perimeterXDelegate != null) {
                        perimeterXDelegate.perimeterxChallengeRenderFailedHandler(mVar.a);
                        break;
                    }
                } else {
                    com.perimeterx.mobile_sdk.session.m mVar2 = dVar.b;
                    PerimeterXDelegate perimeterXDelegate2 = mVar2.c;
                    if (perimeterXDelegate2 != null) {
                        perimeterXDelegate2.perimeterxChallengeRenderedHandler(mVar2.a);
                        break;
                    }
                }
                break;
        }
    }

    public /* synthetic */ RunnableC0142t(boolean z, com.perimeterx.mobile_sdk.session.d dVar) {
        this.a = 2;
        this.b = z;
        this.c = dVar;
    }
}
