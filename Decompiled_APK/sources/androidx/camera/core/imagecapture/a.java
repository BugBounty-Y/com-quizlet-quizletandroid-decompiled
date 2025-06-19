package androidx.camera.core.imagecapture;

import android.util.Size;
import androidx.camera.core.g0;

/* loaded from: classes.dex */
public final class a {
    public g0 a;
    public final g0 b = null;
    public final Size c;
    public final int d;
    public final int e;
    public final boolean f;
    public final androidx.camera.core.processing.d g;
    public final androidx.camera.core.processing.d h;

    public a(Size size, int i, int i2, boolean z, androidx.camera.core.processing.d dVar, androidx.camera.core.processing.d dVar2) {
        if (size == null) {
            throw new NullPointerException("Null size");
        }
        this.c = size;
        this.d = i;
        this.e = i2;
        this.f = z;
        this.g = dVar;
        this.h = dVar2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.c.equals(aVar.c) && this.d == aVar.d && this.e == aVar.e && this.f == aVar.f && this.g.equals(aVar.g) && this.h.equals(aVar.h);
    }

    public final int hashCode() {
        return ((((((((((((this.c.hashCode() ^ 1000003) * 1000003) ^ this.d) * 1000003) ^ this.e) * 1000003) ^ (this.f ? 1231 : 1237)) * 583896283) ^ 35) * 1000003) ^ this.g.hashCode()) * 1000003) ^ this.h.hashCode();
    }

    public final String toString() {
        return "In{size=" + this.c + ", inputFormat=" + this.d + ", outputFormat=" + this.e + ", virtualCamera=" + this.f + ", imageReaderProxyProvider=null, postviewSize=null, postviewImageFormat=35, requestEdge=" + this.g + ", errorEdge=" + this.h + "}";
    }
}
