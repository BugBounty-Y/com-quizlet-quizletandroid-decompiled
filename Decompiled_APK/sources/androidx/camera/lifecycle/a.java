package androidx.camera.lifecycle;

import androidx.lifecycle.J;

/* loaded from: classes.dex */
public final class a {
    public final J a;
    public final androidx.camera.core.internal.a b;

    public a(J j, androidx.camera.core.internal.a aVar) {
        if (j == null) {
            throw new NullPointerException("Null lifecycleOwner");
        }
        this.a = j;
        if (aVar == null) {
            throw new NullPointerException("Null cameraId");
        }
        this.b = aVar;
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
        return "Key{lifecycleOwner=" + this.a + ", cameraId=" + this.b + "}";
    }
}
