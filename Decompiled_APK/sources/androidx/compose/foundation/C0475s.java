package androidx.compose.foundation;

import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.C0850j;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0475s {
    public C0848h a = null;
    public C0844d b = null;
    public androidx.compose.ui.graphics.drawscope.b c = null;
    public C0850j d = null;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0475s)) {
            return false;
        }
        C0475s c0475s = (C0475s) obj;
        return Intrinsics.b(this.a, c0475s.a) && Intrinsics.b(this.b, c0475s.b) && Intrinsics.b(this.c, c0475s.c) && Intrinsics.b(this.d, c0475s.d);
    }

    public final int hashCode() {
        C0848h c0848h = this.a;
        int iHashCode = (c0848h == null ? 0 : c0848h.hashCode()) * 31;
        C0844d c0844d = this.b;
        int iHashCode2 = (iHashCode + (c0844d == null ? 0 : c0844d.hashCode())) * 31;
        androidx.compose.ui.graphics.drawscope.b bVar = this.c;
        int iHashCode3 = (iHashCode2 + (bVar == null ? 0 : bVar.hashCode())) * 31;
        C0850j c0850j = this.d;
        return iHashCode3 + (c0850j != null ? c0850j.hashCode() : 0);
    }

    public final String toString() {
        return "BorderCache(imageBitmap=" + this.a + ", canvas=" + this.b + ", canvasDrawScope=" + this.c + ", borderPath=" + this.d + ')';
    }
}
