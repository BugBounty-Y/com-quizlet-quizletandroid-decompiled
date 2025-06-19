package androidx.glance.text;

import androidx.compose.ui.unit.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final androidx.glance.unit.a a;
    public final m b;
    public final b c;
    public final c d;

    public g(androidx.glance.unit.a aVar, m mVar, b bVar, c cVar) {
        this.a = aVar;
        this.b = mVar;
        this.c = bVar;
        this.d = cVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.glance.unit.a] */
    public static g a(g gVar, androidx.glance.color.a aVar, c cVar, int i) {
        androidx.glance.color.a aVar2 = aVar;
        if ((i & 1) != 0) {
            aVar2 = gVar.a;
        }
        if ((i & 16) != 0) {
            cVar = gVar.d;
        }
        return new g(aVar2, gVar.b, gVar.c, cVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        if (!Intrinsics.b(this.a, gVar.a) || !Intrinsics.b(this.b, gVar.b) || !Intrinsics.b(this.c, gVar.c)) {
            return false;
        }
        gVar.getClass();
        gVar.getClass();
        if (!Intrinsics.b(this.d, gVar.d)) {
            return false;
        }
        gVar.getClass();
        return true;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        m mVar = this.b;
        int iHashCode2 = (iHashCode + (mVar != null ? Long.hashCode(mVar.a) : 0)) * 31;
        b bVar = this.c;
        int iHashCode3 = (iHashCode2 + (bVar != null ? Integer.hashCode(bVar.a) : 0)) * 29791;
        c cVar = this.d;
        return (iHashCode3 + (cVar != null ? Integer.hashCode(cVar.a) : 0)) * 31;
    }

    public final String toString() {
        return "TextStyle(color=" + this.a + ", fontSize=" + this.b + ", fontWeight=" + this.c + ", fontStyle=null, textDecoration=null, textAlign=" + this.d + ", fontFamily=null)";
    }
}
