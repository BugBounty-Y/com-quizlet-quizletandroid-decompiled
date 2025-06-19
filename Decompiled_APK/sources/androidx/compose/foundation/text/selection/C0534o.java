package androidx.compose.foundation.text.selection;

/* renamed from: androidx.compose.foundation.text.selection.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0534o {
    public final long a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final androidx.compose.ui.text.H f;

    public C0534o(long j, int i, int i2, int i3, int i4, androidx.compose.ui.text.H h) {
        this.a = j;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = h;
    }

    public final C0535p a(int i) {
        return new C0535p(W.u(this.f, i), i, this.a);
    }

    public final int b() {
        int i = this.c;
        int i2 = this.d;
        if (i < i2) {
            return 2;
        }
        return i > i2 ? 1 : 3;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectionInfo(id=");
        sb.append(this.a);
        sb.append(", range=(");
        int i = this.c;
        sb.append(i);
        sb.append('-');
        androidx.compose.ui.text.H h = this.f;
        sb.append(W.u(h, i));
        sb.append(',');
        int i2 = this.d;
        sb.append(i2);
        sb.append('-');
        sb.append(W.u(h, i2));
        sb.append("), prevOffset=");
        return android.support.v4.media.session.a.q(sb, this.e, ')');
    }
}
