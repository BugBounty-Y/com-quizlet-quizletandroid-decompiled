package androidx.glance.appwidget;

import android.widget.RemoteViews;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A0 {
    public final RemoteViews a;
    public final C1179k0 b;

    public A0(RemoteViews remoteViews, C1179k0 c1179k0) {
        this.a = remoteViews;
        this.b = c1179k0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A0)) {
            return false;
        }
        A0 a0 = (A0) obj;
        return Intrinsics.b(this.a, a0.a) && Intrinsics.b(this.b, a0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RemoteViewsInfo(remoteViews=" + this.a + ", view=" + this.b + ')';
    }
}
