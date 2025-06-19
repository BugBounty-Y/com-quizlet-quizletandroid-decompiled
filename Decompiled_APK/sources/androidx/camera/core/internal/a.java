package androidx.camera.core.internal;

import androidx.camera.core.impl.C0164d;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final C0164d b;

    public a(String str, C0164d c0164d) {
        if (str == null) {
            throw new NullPointerException("Null cameraIdString");
        }
        this.a = str;
        if (c0164d == null) {
            throw new NullPointerException("Null cameraConfigId");
        }
        this.b = c0164d;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof a) {
            a aVar = (a) obj;
            if (this.a.equals(aVar.a) && this.b.equals(aVar.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode();
    }

    public final String toString() {
        return "CameraId{cameraIdString=" + this.a + ", cameraConfigId=" + this.b + "}";
    }
}
