package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraManager;

/* renamed from: androidx.camera.camera2.internal.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0145w extends CameraManager.AvailabilityCallback {
    public final String a;
    public boolean b = true;
    public final /* synthetic */ C c;

    public C0145w(C c, String str) {
        this.c = c;
        this.a = str;
    }

    @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
    public final void onCameraAvailable(String str) {
        if (this.a.equals(str)) {
            this.b = true;
            if (this.c.H == 4) {
                this.c.J(false);
            }
        }
    }

    @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
    public final void onCameraUnavailable(String str) {
        if (this.a.equals(str)) {
            this.b = false;
        }
    }
}
