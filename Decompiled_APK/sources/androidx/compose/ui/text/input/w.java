package androidx.compose.ui.text.input;

/* loaded from: classes.dex */
public final class w implements InterfaceC1006i {
    public final int a;
    public final int b;

    public w(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        if (c1007j.d != -1) {
            c1007j.d = -1;
            c1007j.e = -1;
        }
        androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) c1007j.f;
        int iC = kotlin.ranges.l.c(this.a, 0, fVar.d());
        int iC2 = kotlin.ranges.l.c(this.b, 0, fVar.d());
        if (iC != iC2) {
            if (iC < iC2) {
                c1007j.f(iC, iC2);
            } else {
                c1007j.f(iC2, iC);
            }
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return this.a == wVar.a && this.b == wVar.b;
    }

    public final int hashCode() {
        return (this.a * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetComposingRegionCommand(start=");
        sb.append(this.a);
        sb.append(", end=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
