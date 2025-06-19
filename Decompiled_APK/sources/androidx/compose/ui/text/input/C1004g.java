package androidx.compose.ui.text.input;

/* renamed from: androidx.compose.ui.text.input.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1004g implements InterfaceC1006i {
    public final int a;
    public final int b;

    public C1004g(int i, int i2) {
        this.a = i;
        this.b = i2;
        if (i < 0 || i2 < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.j("Expected lengthBeforeCursor and lengthAfterCursor to be non-negative, were ", i, " and ", " respectively.", i2).toString());
        }
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        int i = c1007j.c;
        int i2 = this.b;
        int iD = i + i2;
        int i3 = (i ^ iD) & (i2 ^ iD);
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) c1007j.f;
        if (i3 < 0) {
            iD = fVar.d();
        }
        c1007j.b(c1007j.c, Math.min(iD, fVar.d()));
        int i4 = c1007j.b;
        int i5 = this.a;
        int i6 = i4 - i5;
        if (((i4 ^ i6) & (i5 ^ i4)) < 0) {
            i6 = 0;
        }
        c1007j.b(Math.max(0, i6), c1007j.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1004g)) {
            return false;
        }
        C1004g c1004g = (C1004g) obj;
        return this.a == c1004g.a && this.b == c1004g.b;
    }

    public final int hashCode() {
        return (this.a * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DeleteSurroundingTextCommand(lengthBeforeCursor=");
        sb.append(this.a);
        sb.append(", lengthAfterCursor=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
