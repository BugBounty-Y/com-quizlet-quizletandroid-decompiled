package androidx.glance.appwidget;

/* loaded from: classes.dex */
public final class D0 {
    public final u0 a;
    public final boolean b;
    public final boolean c;

    public D0(u0 u0Var, boolean z, boolean z2) {
        this.a = u0Var;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D0)) {
            return false;
        }
        D0 d0 = (D0) obj;
        return this.a == d0.a && this.b == d0.b && this.c == d0.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RowColumnChildSelector(type=");
        sb.append(this.a);
        sb.append(", expandWidth=");
        sb.append(this.b);
        sb.append(", expandHeight=");
        return android.support.v4.media.session.a.u(sb, this.c, ')');
    }
}
