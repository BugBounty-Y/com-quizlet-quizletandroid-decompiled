package androidx.compose.ui.text.input;

/* loaded from: classes.dex */
public final class y implements InterfaceC1006i {
    public final int a;
    public final int b;

    public y(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        int iC = kotlin.ranges.l.c(this.a, 0, ((androidx.compose.ui.text.android.selection.f) c1007j.f).d());
        int iC2 = kotlin.ranges.l.c(this.b, 0, ((androidx.compose.ui.text.android.selection.f) c1007j.f).d());
        if (iC < iC2) {
            c1007j.g(iC, iC2);
        } else {
            c1007j.g(iC2, iC);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return this.a == yVar.a && this.b == yVar.b;
    }

    public final int hashCode() {
        return (this.a * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetSelectionCommand(start=");
        sb.append(this.a);
        sb.append(", end=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
