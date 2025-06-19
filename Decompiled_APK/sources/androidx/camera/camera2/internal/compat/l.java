package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraDevice;
import androidx.camera.camera2.internal.C0144v;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0144v b;
    public final /* synthetic */ CameraDevice c;

    public /* synthetic */ l(C0144v c0144v, CameraDevice cameraDevice, int i) {
        this.a = i;
        this.b = c0144v;
        this.c = cameraDevice;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((CameraDevice.StateCallback) this.b.b).onClosed(this.c);
                break;
            case 1:
                ((CameraDevice.StateCallback) this.b.b).onDisconnected(this.c);
                break;
            default:
                ((CameraDevice.StateCallback) this.b.b).onOpened(this.c);
                break;
        }
    }
}
