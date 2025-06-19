package androidx.compose.ui.text.input;

import androidx.compose.ui.text.C0995g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class x implements InterfaceC1006i {
    public final C0995g a;
    public final int b;

    public x(String str, int i) {
        this.a = new C0995g(6, str, null);
        this.b = i;
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        int i = c1007j.d;
        boolean z = i != -1;
        C0995g c0995g = this.a;
        if (z) {
            c1007j.e(i, c1007j.e, c0995g.a);
            String str = c0995g.a;
            if (str.length() > 0) {
                c1007j.f(i, str.length() + i);
            }
        } else {
            int i2 = c1007j.b;
            c1007j.e(i2, c1007j.c, c0995g.a);
            String str2 = c0995g.a;
            if (str2.length() > 0) {
                c1007j.f(i2, str2.length() + i2);
            }
        }
        int i3 = c1007j.b;
        int i4 = c1007j.c;
        int i5 = i3 == i4 ? i4 : -1;
        int i6 = this.b;
        int iC = kotlin.ranges.l.c(i6 > 0 ? (i5 + i6) - 1 : (i5 + i6) - c0995g.a.length(), 0, ((androidx.compose.ui.text.android.selection.f) c1007j.f).d());
        c1007j.g(iC, iC);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return Intrinsics.b(this.a.a, xVar.a.a) && this.b == xVar.b;
    }

    public final int hashCode() {
        return (this.a.a.hashCode() * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetComposingTextCommand(text='");
        sb.append(this.a.a);
        sb.append("', newCursorPosition=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
