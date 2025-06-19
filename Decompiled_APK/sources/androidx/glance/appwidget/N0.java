package androidx.glance.appwidget;

import android.content.ComponentName;
import android.content.Context;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N0 {
    public final Context a;
    public final int b;
    public final boolean c;
    public final C1185n0 d;
    public final int e;
    public final boolean f;
    public final AtomicInteger g;
    public final C1179k0 h;
    public final AtomicBoolean i;
    public final long j;
    public final int k;
    public final boolean l;
    public final Integer m;
    public final ComponentName n;

    public N0(Context context, int i, boolean z, C1185n0 c1185n0, int i2, boolean z2, AtomicInteger atomicInteger, C1179k0 c1179k0, AtomicBoolean atomicBoolean, long j, int i3, boolean z3, Integer num, ComponentName componentName) {
        this.a = context;
        this.b = i;
        this.c = z;
        this.d = c1185n0;
        this.e = i2;
        this.f = z2;
        this.g = atomicInteger;
        this.h = c1179k0;
        this.i = atomicBoolean;
        this.j = j;
        this.k = i3;
        this.l = z3;
        this.m = num;
        this.n = componentName;
    }

    public static N0 a(N0 n0, int i, AtomicInteger atomicInteger, C1179k0 c1179k0, AtomicBoolean atomicBoolean, long j, int i2, Integer num, int i3) {
        Context context = n0.a;
        int i4 = n0.b;
        boolean z = n0.c;
        C1185n0 c1185n0 = n0.d;
        int i5 = (i3 & 16) != 0 ? n0.e : i;
        boolean z2 = (i3 & 32) != 0 ? n0.f : true;
        AtomicInteger atomicInteger2 = (i3 & 64) != 0 ? n0.g : atomicInteger;
        C1179k0 c1179k02 = (i3 & 128) != 0 ? n0.h : c1179k0;
        AtomicBoolean atomicBoolean2 = (i3 & 256) != 0 ? n0.i : atomicBoolean;
        long j2 = (i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? n0.j : j;
        int i6 = (i3 & 1024) != 0 ? n0.k : i2;
        n0.getClass();
        boolean z3 = (i3 & 4096) != 0 ? n0.l : true;
        Integer num2 = (i3 & 8192) != 0 ? n0.m : num;
        ComponentName componentName = n0.n;
        n0.getClass();
        return new N0(context, i4, z, c1185n0, i5, z2, atomicInteger2, c1179k02, atomicBoolean2, j2, i6, z3, num2, componentName);
    }

    public final N0 b(C1179k0 c1179k0, int i) {
        return a(this, i, null, c1179k0, null, 0L, 0, null, 32623);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof N0) {
            N0 n0 = (N0) obj;
            if (this.a.equals(n0.a) && this.b == n0.b && this.c == n0.c && this.d.equals(n0.d) && this.e == n0.e && this.f == n0.f && Intrinsics.b(this.g, n0.g) && Intrinsics.b(this.h, n0.h) && Intrinsics.b(this.i, n0.i) && this.j == n0.j && this.k == n0.k && this.l == n0.l && Intrinsics.b(this.m, n0.m) && Intrinsics.b(this.n, n0.n)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(-1, androidx.compose.animation.d0.b(this.k, androidx.compose.animation.d0.d((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.e, (this.d.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c)) * 31, 31), 31, this.f)) * 31)) * 31)) * 31, 31, this.j), 31), 31), 31, this.l);
        Integer num = this.m;
        int iHashCode = (iG + (num == null ? 0 : num.hashCode())) * 31;
        ComponentName componentName = this.n;
        return iHashCode + (componentName != null ? componentName.hashCode() : 0);
    }

    public final String toString() {
        return "TranslationContext(context=" + this.a + ", appWidgetId=" + this.b + ", isRtl=" + this.c + ", layoutConfiguration=" + this.d + ", itemPosition=" + this.e + ", isLazyCollectionDescendant=" + this.f + ", lastViewId=" + this.g + ", parentContext=" + this.h + ", isBackgroundSpecified=" + this.i + ", layoutSize=" + ((Object) androidx.compose.ui.unit.g.c(this.j)) + ", layoutCollectionViewId=" + this.k + ", layoutCollectionItemId=-1, canUseSelectableGroup=" + this.l + ", actionTargetId=" + this.m + ", actionBroadcastReceiver=" + this.n + ')';
    }
}
