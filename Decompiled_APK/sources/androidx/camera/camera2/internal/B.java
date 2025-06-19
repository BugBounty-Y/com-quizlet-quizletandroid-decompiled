package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraDevice;
import android.os.SystemClock;
import androidx.camera.core.C0153e;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class B extends CameraDevice.StateCallback {
    public final androidx.camera.core.impl.utils.executor.k a;
    public final androidx.camera.core.impl.utils.executor.e b;
    public A c;
    public ScheduledFuture d;
    public final C0148z e;
    public final /* synthetic */ C f;

    public B(C c, androidx.camera.core.impl.utils.executor.k kVar, androidx.camera.core.impl.utils.executor.e eVar, long j) {
        this.f = c;
        this.a = kVar;
        this.b = eVar;
        this.e = new C0148z(this, j);
    }

    public final boolean a() {
        if (this.d == null) {
            return false;
        }
        this.f.t("Cancelling scheduled re-open: " + this.c);
        this.c.b = true;
        this.c = null;
        this.d.cancel(false);
        this.d = null;
        return true;
    }

    public final void b() {
        AbstractC3242q6.h(null, this.c == null);
        AbstractC3242q6.h(null, this.d == null);
        C0148z c0148z = this.e;
        c0148z.getClass();
        long jUptimeMillis = SystemClock.uptimeMillis();
        if (c0148z.c == -1) {
            c0148z.c = jUptimeMillis;
        }
        long j = jUptimeMillis - c0148z.c;
        long jC = c0148z.c();
        C c = this.f;
        if (j >= jC) {
            c0148z.c = -1L;
            AbstractC3053s1.c("Camera2CameraImpl", "Camera reopening attempted for " + c0148z.c() + "ms without success.");
            c.E(4, null, false);
            return;
        }
        this.c = new A(this, this.a);
        c.t("Attempting camera re-open in " + c0148z.b() + "ms: " + this.c + " activeResuming = " + c.C);
        this.d = this.b.schedule(this.c, (long) c0148z.b(), TimeUnit.MILLISECONDS);
    }

    public final boolean c() {
        C c = this.f;
        if (!c.C) {
            return false;
        }
        int i = c.k;
        return i == 1 || i == 2;
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onClosed(CameraDevice cameraDevice) {
        this.f.t("CameraDevice.onClosed()");
        AbstractC3242q6.h("Unexpected onClose callback on camera device: " + cameraDevice, this.f.j == null);
        int iK = AbstractC0147y.k(this.f.H);
        if (iK == 1 || iK == 4) {
            AbstractC3242q6.h(null, this.f.m.isEmpty());
            this.f.r();
        } else {
            if (iK != 5 && iK != 6) {
                throw new IllegalStateException("Camera closed while in state: ".concat(AbstractC0147y.l(this.f.H)));
            }
            C c = this.f;
            int i = c.k;
            if (i == 0) {
                c.J(false);
            } else {
                c.t("Camera closed due to error: ".concat(C.v(i)));
                b();
            }
        }
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onDisconnected(CameraDevice cameraDevice) {
        this.f.t("CameraDevice.onDisconnected()");
        onError(cameraDevice, 1);
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onError(CameraDevice cameraDevice, int i) {
        C c = this.f;
        c.j = cameraDevice;
        c.k = i;
        com.quizlet.data.interactor.school.b bVar = c.G;
        ((C) bVar.c).t("Camera receive onErrorCallback");
        bVar.j();
        int iK = AbstractC0147y.k(this.f.H);
        if (iK != 1) {
            switch (iK) {
                case 4:
                    break;
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                    cameraDevice.getId();
                    AbstractC0147y.j(this.f.H);
                    int i2 = 3;
                    AbstractC3053s1.f(3, "Camera2CameraImpl");
                    AbstractC3242q6.h("Attempt to handle open error from non open state: ".concat(AbstractC0147y.l(this.f.H)), this.f.H == 8 || this.f.H == 9 || this.f.H == 10 || this.f.H == 7 || this.f.H == 6);
                    if (i != 1 && i != 2 && i != 4) {
                        AbstractC3053s1.c("Camera2CameraImpl", "Error observed on open (or opening) camera device " + cameraDevice.getId() + ": " + C.v(i) + " closing camera.");
                        this.f.E(5, new C0153e(i == 3 ? 5 : 6, null), true);
                        this.f.q();
                        return;
                    }
                    cameraDevice.getId();
                    AbstractC3053s1.f(3, "Camera2CameraImpl");
                    C c2 = this.f;
                    AbstractC3242q6.h("Can only reopen camera device after error if the camera device is actually in an error state.", c2.k != 0);
                    if (i == 1) {
                        i2 = 2;
                    } else if (i == 2) {
                        i2 = 1;
                    }
                    c2.E(7, new C0153e(i2, null), true);
                    c2.q();
                    return;
                default:
                    throw new IllegalStateException("onError() should not be possible from state: ".concat(AbstractC0147y.l(this.f.H)));
            }
        }
        String id = cameraDevice.getId();
        String strV = C.v(i);
        String strJ = AbstractC0147y.j(this.f.H);
        StringBuilder sbH = AbstractC0147y.h("CameraDevice.onError(): ", id, " failed with ", strV, " while in ");
        sbH.append(strJ);
        sbH.append(" state. Will finish closing camera.");
        AbstractC3053s1.c("Camera2CameraImpl", sbH.toString());
        this.f.q();
    }

    @Override // android.hardware.camera2.CameraDevice.StateCallback
    public final void onOpened(CameraDevice cameraDevice) {
        this.f.t("CameraDevice.onOpened()");
        C c = this.f;
        c.j = cameraDevice;
        c.k = 0;
        this.e.c = -1L;
        int iK = AbstractC0147y.k(c.H);
        if (iK == 1 || iK == 4) {
            AbstractC3242q6.h(null, this.f.m.isEmpty());
            this.f.j.close();
            this.f.j = null;
        } else {
            if (iK != 5 && iK != 6 && iK != 7) {
                throw new IllegalStateException("onOpened() should not be possible from state: ".concat(AbstractC0147y.l(this.f.H)));
            }
            this.f.F(9);
            androidx.camera.core.impl.D d = this.f.q;
            String id = cameraDevice.getId();
            C c2 = this.f;
            if (d.e(id, c2.p.z(c2.j.getId()))) {
                this.f.B();
            }
        }
    }
}
