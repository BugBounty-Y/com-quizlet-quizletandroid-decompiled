package androidx.camera.core.processing.concurrent;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.core.processing.k;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class b {
    public final k a;
    public final k b;
    public final ArrayList c;

    public b(k kVar, k kVar2, ArrayList arrayList) {
        if (kVar == null) {
            throw new NullPointerException("Null primarySurfaceEdge");
        }
        this.a = kVar;
        if (kVar2 == null) {
            throw new NullPointerException("Null secondarySurfaceEdge");
        }
        this.b = kVar2;
        this.c = arrayList;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b.equals(bVar.b) && this.c.equals(bVar.c);
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("In{primarySurfaceEdge=");
        sb.append(this.a);
        sb.append(", secondarySurfaceEdge=");
        sb.append(this.b);
        sb.append(", outConfigs=");
        return AbstractC0147y.f("}", sb, this.c);
    }
}
