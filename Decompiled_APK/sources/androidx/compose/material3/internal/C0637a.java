package androidx.compose.material3.internal;

/* renamed from: androidx.compose.material3.internal.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0637a implements J {
    public final androidx.compose.ui.g a;
    public final androidx.compose.ui.g b;
    public final int c;

    public C0637a(androidx.compose.ui.g gVar, androidx.compose.ui.g gVar2, int i) {
        this.a = gVar;
        this.b = gVar2;
        this.c = i;
    }

    @Override // androidx.compose.material3.internal.J
    public final int a(androidx.compose.ui.unit.i iVar, long j, int i, androidx.compose.ui.unit.k kVar) {
        int iA = this.b.a(0, iVar.b(), kVar);
        int i2 = -this.a.a(0, i, kVar);
        androidx.compose.ui.unit.k kVar2 = androidx.compose.ui.unit.k.a;
        int i3 = this.c;
        if (kVar != kVar2) {
            i3 = -i3;
        }
        return iVar.a + iA + i2 + i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0637a)) {
            return false;
        }
        C0637a c0637a = (C0637a) obj;
        return this.a.equals(c0637a.a) && this.b.equals(c0637a.b) && this.c == c0637a.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + android.support.v4.media.session.a.b(Float.hashCode(this.a.a) * 31, this.b.a, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Horizontal(menuAlignment=");
        sb.append(this.a);
        sb.append(", anchorAlignment=");
        sb.append(this.b);
        sb.append(", offset=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
