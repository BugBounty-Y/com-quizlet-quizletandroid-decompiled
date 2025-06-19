package androidx.camera.core.impl;

import com.google.android.gms.internal.measurement.AbstractC3053s1;

/* loaded from: classes.dex */
public final class B implements androidx.camera.core.Z {
    public final /* synthetic */ int b;
    public final androidx.camera.core.Z c;

    public B(int i, long j) {
        this.b = i;
        switch (i) {
            case 1:
                this.c = new w0(j, new A(j));
                break;
            default:
                this.c = new B(1, j);
                break;
        }
    }

    @Override // androidx.camera.core.Z
    public final long a() {
        switch (this.b) {
            case 0:
                return ((w0) ((B) this.c).c).b;
            default:
                return ((w0) this.c).b;
        }
    }

    @Override // androidx.camera.core.Z
    public final androidx.camera.core.Y b(C0186z c0186z) {
        switch (this.b) {
            case 0:
                if (((w0) ((B) this.c).c).b(c0186z).b) {
                    return androidx.camera.core.Y.e;
                }
                Throwable th = (Throwable) c0186z.d;
                if (th instanceof CameraValidator$CameraIdListIncorrectException) {
                    AbstractC3053s1.c("CameraX", "The device might underreport the amount of the cameras. Finish the initialize task since we are already reaching the maximum number of retries.");
                    if (((CameraValidator$CameraIdListIncorrectException) th).a > 0) {
                        return androidx.camera.core.Y.f;
                    }
                }
                return androidx.camera.core.Y.d;
            default:
                return ((w0) this.c).b(c0186z);
        }
    }
}
