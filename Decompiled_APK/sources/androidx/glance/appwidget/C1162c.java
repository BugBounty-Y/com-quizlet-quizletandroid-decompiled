package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1162c {
    public final int a;

    public C1162c(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C1162c) && this.a == ((C1162c) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("AppWidgetId(appWidgetId="), this.a, ')');
    }
}
