package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1187o0 {
    public final int a;

    public C1187o0(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C1187o0) && this.a == ((C1187o0) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("LayoutInfo(layoutId="), this.a, ')');
    }
}
