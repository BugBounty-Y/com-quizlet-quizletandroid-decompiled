package it.sephiroth.android.library.xtooltip;

/* loaded from: classes3.dex */
public final class a {
    public static final a b = new a(10);
    public static final a c = new a(6);
    public final int a;

    public a(int i) {
        this.a = i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClosePolicy{policy: ");
        int i = this.a;
        sb.append(i);
        sb.append(", inside:true, outside: ");
        sb.append((i & 4) == 4);
        sb.append(", anywhere: ");
        sb.append((i & 4) == 4);
        sb.append(", consume: ");
        return android.support.v4.media.session.a.u(sb, (i & 8) == 8, '}');
    }
}
