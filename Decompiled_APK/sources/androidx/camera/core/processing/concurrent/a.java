package androidx.camera.core.processing.concurrent;

/* loaded from: classes.dex */
public final class a {
    public final androidx.camera.core.processing.util.b a;
    public final androidx.camera.core.processing.util.b b;

    public a(androidx.camera.core.processing.util.b bVar, androidx.camera.core.processing.util.b bVar2) {
        this.a = bVar;
        this.b = bVar2;
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
        return "DualOutConfig{primaryOutConfig=" + this.a + ", secondaryOutConfig=" + this.b + "}";
    }
}
