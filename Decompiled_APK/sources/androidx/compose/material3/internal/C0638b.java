package androidx.compose.material3.internal;

/* renamed from: androidx.compose.material3.internal.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0638b implements K {
    public final androidx.compose.ui.h a;
    public final androidx.compose.ui.h b;
    public final int c;

    public C0638b(androidx.compose.ui.h hVar, androidx.compose.ui.h hVar2, int i) {
        this.a = hVar;
        this.b = hVar2;
        this.c = i;
    }

    @Override // androidx.compose.material3.internal.K
    public final int a(androidx.compose.ui.unit.i iVar, long j, int i) {
        int iA = this.b.a(0, iVar.a());
        return iVar.b + iA + (-this.a.a(0, i)) + this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0638b)) {
            return false;
        }
        C0638b c0638b = (C0638b) obj;
        return this.a.equals(c0638b.a) && this.b.equals(c0638b.b) && this.c == c0638b.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + android.support.v4.media.session.a.b(Float.hashCode(this.a.a) * 31, this.b.a, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Vertical(menuAlignment=");
        sb.append(this.a);
        sb.append(", anchorAlignment=");
        sb.append(this.b);
        sb.append(", offset=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
