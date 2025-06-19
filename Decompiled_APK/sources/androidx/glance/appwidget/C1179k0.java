package androidx.glance.appwidget;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.glance.appwidget.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1179k0 {
    public final int a;
    public final int b;
    public final Map c;

    public C1179k0(int i, int i2, Map map) {
        this.a = i;
        this.b = i2;
        this.c = map;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1179k0)) {
            return false;
        }
        C1179k0 c1179k0 = (C1179k0) obj;
        return this.a == c1179k0.a && this.b == c1179k0.b && Intrinsics.b(this.c, c1179k0.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        return "InsertedViewInfo(mainViewId=" + this.a + ", complexViewId=" + this.b + ", children=" + this.c + ')';
    }

    public /* synthetic */ C1179k0(int i, int i2, Map map, int i3) {
        this((i3 & 1) != 0 ? -1 : i, (i3 & 2) != 0 ? -1 : i2, (i3 & 4) != 0 ? kotlin.collections.V.c() : map);
    }
}
