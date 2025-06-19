package coil3.fetch;

import androidx.compose.animation.d0;
import coil3.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements e {
    public final j a;
    public final boolean b;
    public final coil3.decode.h c;

    public h(j jVar, boolean z, coil3.decode.h hVar) {
        this.a = jVar;
        this.b = z;
        this.c = hVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b && this.c == hVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "ImageFetchResult(image=" + this.a + ", isSampled=" + this.b + ", dataSource=" + this.c + ')';
    }
}
