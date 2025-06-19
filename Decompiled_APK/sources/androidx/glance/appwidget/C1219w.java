package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1219w {
    public final int a;

    public C1219w(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C1219w) && this.a == ((C1219w) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("ContainerInfo(layoutId="), this.a, ')');
    }
}
