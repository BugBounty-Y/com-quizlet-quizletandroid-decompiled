package androidx.camera.camera2.internal;

/* renamed from: androidx.camera.camera2.internal.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0126c {
    public final int a;
    public final int b;
    public final boolean c;
    public final boolean d;

    public C0126c(int i, int i2, boolean z, boolean z2) {
        this.a = i;
        this.b = i2;
        this.c = z;
        this.d = z2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0126c) {
            C0126c c0126c = (C0126c) obj;
            if (this.a == c0126c.a && this.b == c0126c.b && this.c == c0126c.c && this.d == c0126c.d) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((((this.a ^ 1000003) * 1000003) ^ this.b) * 1000003) ^ (this.c ? 1231 : 1237)) * 1000003) ^ (this.d ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FeatureSettings{cameraMode=");
        sb.append(this.a);
        sb.append(", requiredMaxBitDepth=");
        sb.append(this.b);
        sb.append(", previewStabilizationOn=");
        sb.append(this.c);
        sb.append(", ultraHdrOn=");
        return android.support.v4.media.session.a.o("}", sb, this.d);
    }
}
