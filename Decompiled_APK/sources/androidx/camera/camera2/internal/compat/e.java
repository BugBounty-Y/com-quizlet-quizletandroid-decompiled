package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraCaptureSession;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;
    public final /* synthetic */ CameraCaptureSession c;

    public /* synthetic */ e(f fVar, CameraCaptureSession cameraCaptureSession, int i) {
        this.a = i;
        this.b = fVar;
        this.c = cameraCaptureSession;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a.onActive(this.c);
                break;
            case 1:
                this.b.a.onClosed(this.c);
                break;
            case 2:
                this.b.a.onCaptureQueueEmpty(this.c);
                break;
            case 3:
                this.b.a.onConfigured(this.c);
                break;
            case 4:
                this.b.a.onReady(this.c);
                break;
            default:
                this.b.a.onConfigureFailed(this.c);
                break;
        }
    }
}
