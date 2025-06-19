package androidx.compose.ui.text.input;

import androidx.compose.ui.text.C0995g;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.input.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0998a implements InterfaceC1006i {
    public final C0995g a;
    public final int b;

    public C0998a(C0995g c0995g, int i) {
        this.a = c0995g;
        this.b = i;
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        int i = c1007j.d;
        boolean z = i != -1;
        C0995g c0995g = this.a;
        if (z) {
            c1007j.e(i, c1007j.e, c0995g.a);
        } else {
            c1007j.e(c1007j.b, c1007j.c, c0995g.a);
        }
        int i2 = c1007j.b;
        int i3 = c1007j.c;
        int i4 = i2 == i3 ? i3 : -1;
        int i5 = this.b;
        int iC = kotlin.ranges.l.c(i5 > 0 ? (i4 + i5) - 1 : (i4 + i5) - c0995g.a.length(), 0, ((androidx.compose.ui.text.android.selection.f) c1007j.f).d());
        c1007j.g(iC, iC);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0998a)) {
            return false;
        }
        C0998a c0998a = (C0998a) obj;
        return Intrinsics.b(this.a.a, c0998a.a.a) && this.b == c0998a.b;
    }

    public final int hashCode() {
        return (this.a.a.hashCode() * 31) + this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CommitTextCommand(text='");
        sb.append(this.a.a);
        sb.append("', newCursorPosition=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }

    public C0998a(String str, int i) {
        this(new C0995g(6, str, null), i);
    }
}
