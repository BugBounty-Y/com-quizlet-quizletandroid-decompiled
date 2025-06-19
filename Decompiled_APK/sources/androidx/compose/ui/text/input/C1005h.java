package androidx.compose.ui.text.input;

/* renamed from: androidx.compose.ui.text.input.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1005h implements InterfaceC1006i {
    public final int a;
    public final int b;

    public C1005h(int i, int i2) {
        this.a = i;
        this.b = i2;
        if (i < 0 || i2 < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.j("Expected lengthBeforeCursor and lengthAfterCursor to be non-negative, were ", i, " and ", " respectively.", i2).toString());
        }
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        while (true) {
            if (i2 < this.a) {
                int i4 = i3 + 1;
                int i5 = c1007j.b;
                if (i5 <= i4) {
                    i3 = i5;
                    break;
                } else {
                    i3 = (Character.isHighSurrogate(c1007j.c((i5 - i4) + (-1))) && Character.isLowSurrogate(c1007j.c(c1007j.b - i4))) ? i3 + 2 : i4;
                    i2++;
                }
            } else {
                break;
            }
        }
        int iD = 0;
        while (true) {
            if (i >= this.b) {
                break;
            }
            int i6 = iD + 1;
            int i7 = c1007j.c + i6;
            androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) c1007j.f;
            if (i7 >= fVar.d()) {
                iD = fVar.d() - c1007j.c;
                break;
            } else {
                iD = (Character.isHighSurrogate(c1007j.c((c1007j.c + i6) + (-1))) && Character.isLowSurrogate(c1007j.c(c1007j.c + i6))) ? iD + 2 : i6;
                i++;
            }
        }
        int i8 = c1007j.c;
        c1007j.b(i8, iD + i8);
        int i9 = c1007j.b;
        c1007j.b(i9 - i3, i9);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1005h)) {
            return false;
        }
        C1005h c1005h = (C1005h) obj;
        return this.a == c1005h.a && this.b == c1005h.b;
    }

    public final int hashCode() {
        return (this.a * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DeleteSurroundingTextInCodePointsCommand(lengthBeforeCursor=");
        sb.append(this.a);
        sb.append(", lengthAfterCursor=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
