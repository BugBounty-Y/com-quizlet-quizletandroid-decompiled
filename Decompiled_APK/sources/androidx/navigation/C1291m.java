package androidx.navigation;

import android.os.Bundle;
import androidx.lifecycle.B0;
import androidx.lifecycle.C0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.y0;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1291m implements androidx.lifecycle.J, C0, InterfaceC1261w, androidx.savedstate.f {
    public final androidx.navigation.internal.d a;
    public B b;
    public final Bundle c;
    public final androidx.lifecycle.B d;
    public final C1296s e;
    public final String f;
    public final Bundle g;
    public final androidx.navigation.internal.c h = new androidx.navigation.internal.c(this);

    public C1291m(androidx.navigation.internal.d dVar, B b, Bundle bundle, androidx.lifecycle.B b2, C1296s c1296s, String str, Bundle bundle2) {
        this.a = dVar;
        this.b = b;
        this.c = bundle;
        this.d = b2;
        this.e = c1296s;
        this.f = str;
        this.g = bundle2;
        kotlin.l.b(new C1247h(this, 2));
    }

    public final void a(androidx.lifecycle.B maxState) {
        Intrinsics.checkNotNullParameter(maxState, "value");
        androidx.navigation.internal.c cVar = this.h;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(maxState, "maxState");
        cVar.k = maxState;
        cVar.b();
    }

    public final boolean equals(Object obj) {
        Set<String> setKeySet;
        if (obj != null && (obj instanceof C1291m)) {
            C1291m c1291m = (C1291m) obj;
            if (Intrinsics.b(this.f, c1291m.f) && Intrinsics.b(this.b, c1291m.b) && Intrinsics.b(this.h.j, c1291m.h.j) && Intrinsics.b(getSavedStateRegistry(), c1291m.getSavedStateRegistry())) {
                Bundle bundle = this.c;
                Bundle bundle2 = c1291m.c;
                if (Intrinsics.b(bundle, bundle2)) {
                    return true;
                }
                if (bundle != null && (setKeySet = bundle.keySet()) != null) {
                    Set<String> set = setKeySet;
                    if ((set instanceof Collection) && set.isEmpty()) {
                        return true;
                    }
                    for (String str : set) {
                        if (!Intrinsics.b(bundle.get(str), bundle2 != null ? bundle2.get(str) : null)) {
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0038  */
    @Override // androidx.lifecycle.InterfaceC1261w
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.lifecycle.viewmodel.c getDefaultViewModelCreationExtras() {
        /*
            r4 = this;
            androidx.navigation.internal.c r0 = r4.h
            r0.getClass()
            androidx.lifecycle.viewmodel.e r1 = new androidx.lifecycle.viewmodel.e
            r2 = 0
            r1.<init>(r2)
            com.google.firebase.heartbeatinfo.e r2 = androidx.lifecycle.p0.a
            androidx.navigation.m r3 = r0.a
            r1.b(r2, r3)
            com.google.firebase.perf.logging.b r2 = androidx.lifecycle.p0.b
            r1.b(r2, r3)
            android.os.Bundle r0 = r0.a()
            if (r0 == 0) goto L22
            com.google.mlkit.common.internal.model.a r2 = androidx.lifecycle.p0.c
            r1.b(r2, r0)
        L22:
            r0 = 0
            androidx.navigation.internal.d r2 = r4.a
            if (r2 == 0) goto L38
            android.content.Context r2 = r2.a
            if (r2 == 0) goto L30
            android.content.Context r2 = r2.getApplicationContext()
            goto L31
        L30:
            r2 = r0
        L31:
            boolean r3 = r2 instanceof android.app.Application
            if (r3 == 0) goto L38
            android.app.Application r2 = (android.app.Application) r2
            goto L39
        L38:
            r2 = r0
        L39:
            if (r2 == 0) goto L3c
            r0 = r2
        L3c:
            if (r0 == 0) goto L43
            com.google.mlkit.common.sdkinternal.b r2 = androidx.lifecycle.x0.d
            r1.b(r2, r0)
        L43:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.C1291m.getDefaultViewModelCreationExtras():androidx.lifecycle.viewmodel.c");
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return this.h.l;
    }

    @Override // androidx.lifecycle.J
    public final androidx.lifecycle.C getLifecycle() {
        return this.h.j;
    }

    @Override // androidx.savedstate.f
    public final androidx.savedstate.d getSavedStateRegistry() {
        return this.h.h.b;
    }

    @Override // androidx.lifecycle.C0
    public final B0 getViewModelStore() {
        androidx.navigation.internal.c cVar = this.h;
        if (!cVar.i) {
            throw new IllegalStateException("You cannot access the NavBackStackEntry's ViewModels until it is added to the NavController's back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state).");
        }
        if (cVar.j.d == androidx.lifecycle.B.a) {
            throw new IllegalStateException("You cannot access the NavBackStackEntry's ViewModels after the NavBackStackEntry is destroyed.");
        }
        C1296s c1296s = cVar.e;
        if (c1296s == null) {
            throw new IllegalStateException("You must call setViewModelStore() on your NavHostController before accessing the ViewModelStore of a navigation graph.");
        }
        String backStackEntryId = cVar.f;
        Intrinsics.checkNotNullParameter(backStackEntryId, "backStackEntryId");
        LinkedHashMap linkedHashMap = c1296s.b;
        B0 b0 = (B0) linkedHashMap.get(backStackEntryId);
        if (b0 != null) {
            return b0;
        }
        B0 b02 = new B0();
        linkedHashMap.put(backStackEntryId, b02);
        return b02;
    }

    public final int hashCode() {
        Set<String> setKeySet;
        int iHashCode = this.b.hashCode() + (this.f.hashCode() * 31);
        Bundle bundle = this.c;
        if (bundle != null && (setKeySet = bundle.keySet()) != null) {
            Iterator<T> it2 = setKeySet.iterator();
            while (it2.hasNext()) {
                int i = iHashCode * 31;
                Object obj = bundle.get((String) it2.next());
                iHashCode = i + (obj != null ? obj.hashCode() : 0);
            }
        }
        return getSavedStateRegistry().hashCode() + ((this.h.j.hashCode() + (iHashCode * 31)) * 31);
    }

    public final String toString() {
        return this.h.toString();
    }
}
