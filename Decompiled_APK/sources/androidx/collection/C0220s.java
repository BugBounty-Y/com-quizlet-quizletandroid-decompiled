package androidx.collection;

import android.view.View;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.L0;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.collection.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0220s {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public int d;
    public int e;
    public final Object f;
    public final Object g;

    public C0220s(int i) {
        this.a = 0;
        this.b = i;
        if (i <= 0) {
            androidx.collection.internal.a.c("maxSize <= 0");
            throw null;
        }
        this.f = new androidx.collection.internal.b();
        this.g = new com.google.mlkit.common.internal.model.a(2);
    }

    public static void m(Object key, Object value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
    }

    public void a() {
        View view = (View) android.support.v4.media.session.a.e(1, (ArrayList) this.f);
        L0 l0 = (L0) view.getLayoutParams();
        this.c = ((StaggeredGridLayoutManager) this.g).r.b(view);
        l0.getClass();
    }

    public void b() {
        ((ArrayList) this.f).clear();
        this.b = Integer.MIN_VALUE;
        this.c = Integer.MIN_VALUE;
        this.d = 0;
    }

    public Object c(Object key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return null;
    }

    public int d() {
        return ((StaggeredGridLayoutManager) this.g).w ? f(r1.size() - 1, -1) : f(0, ((ArrayList) this.f).size());
    }

    public int e() {
        return ((StaggeredGridLayoutManager) this.g).w ? f(0, ((ArrayList) this.f).size()) : f(r1.size() - 1, -1);
    }

    public int f(int i, int i2) {
        StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) this.g;
        int iK = staggeredGridLayoutManager.r.k();
        int iG = staggeredGridLayoutManager.r.g();
        int i3 = i2 > i ? 1 : -1;
        while (i != i2) {
            View view = (View) ((ArrayList) this.f).get(i);
            int iE = staggeredGridLayoutManager.r.e(view);
            int iB = staggeredGridLayoutManager.r.b(view);
            boolean z = iE <= iG;
            boolean z2 = iB >= iK;
            if (z && z2 && (iE < iK || iB > iG)) {
                return AbstractC1381n0.K(view);
            }
            i += i3;
        }
        return -1;
    }

    public Object g(Object key) {
        Object value;
        Intrinsics.checkNotNullParameter(key, "key");
        synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
            androidx.collection.internal.b bVar = (androidx.collection.internal.b) this.f;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(key, "key");
            Object obj = bVar.a.get(key);
            if (obj != null) {
                this.d++;
                return obj;
            }
            this.e++;
            Object oldValue = c(key);
            if (oldValue == null) {
                return null;
            }
            synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
                androidx.collection.internal.b bVar2 = (androidx.collection.internal.b) this.f;
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(oldValue, "value");
                value = bVar2.a.put(key, oldValue);
                if (value != null) {
                    androidx.collection.internal.b bVar3 = (androidx.collection.internal.b) this.f;
                    bVar3.getClass();
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(value, "value");
                    bVar3.a.put(key, value);
                } else {
                    int i = this.c;
                    m(key, oldValue);
                    this.c = i + 1;
                    Unit unit = Unit.a;
                }
            }
            if (value == null) {
                o(this.b);
                return oldValue;
            }
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(oldValue, "oldValue");
            return value;
        }
    }

    public int h(int i) {
        int i2 = this.c;
        if (i2 != Integer.MIN_VALUE) {
            return i2;
        }
        if (((ArrayList) this.f).size() == 0) {
            return i;
        }
        a();
        return this.c;
    }

    public View i(int i, int i2) {
        StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) this.g;
        ArrayList arrayList = (ArrayList) this.f;
        View view = null;
        if (i2 != -1) {
            int size = arrayList.size() - 1;
            while (size >= 0) {
                View view2 = (View) arrayList.get(size);
                if ((staggeredGridLayoutManager.w && AbstractC1381n0.K(view2) >= i) || ((!staggeredGridLayoutManager.w && AbstractC1381n0.K(view2) <= i) || !view2.hasFocusable())) {
                    break;
                }
                size--;
                view = view2;
            }
            return view;
        }
        int size2 = arrayList.size();
        int i3 = 0;
        while (i3 < size2) {
            View view3 = (View) arrayList.get(i3);
            if ((staggeredGridLayoutManager.w && AbstractC1381n0.K(view3) <= i) || ((!staggeredGridLayoutManager.w && AbstractC1381n0.K(view3) >= i) || !view3.hasFocusable())) {
                break;
            }
            i3++;
            view = view3;
        }
        return view;
    }

    public int j(int i) {
        int i2 = this.b;
        if (i2 != Integer.MIN_VALUE) {
            return i2;
        }
        if (((ArrayList) this.f).size() == 0) {
            return i;
        }
        View view = (View) ((ArrayList) this.f).get(0);
        L0 l0 = (L0) view.getLayoutParams();
        this.b = ((StaggeredGridLayoutManager) this.g).r.e(view);
        l0.getClass();
        return this.b;
    }

    public Object k(Object key, Object value) {
        Object oldValue;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
            try {
                int i = this.c;
                m(key, value);
                this.c = i + 1;
                androidx.collection.internal.b bVar = (androidx.collection.internal.b) this.f;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(value, "value");
                oldValue = bVar.a.put(key, value);
                if (oldValue != null) {
                    int i2 = this.c;
                    m(key, oldValue);
                    this.c = i2 - 1;
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (oldValue != null) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(oldValue, "oldValue");
        }
        o(this.b);
        return oldValue;
    }

    public void l(Object key) {
        Object oldValue;
        Intrinsics.checkNotNullParameter(key, "key");
        synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
            try {
                androidx.collection.internal.b bVar = (androidx.collection.internal.b) this.f;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(key, "key");
                oldValue = bVar.a.remove(key);
                if (oldValue != null) {
                    int i = this.c;
                    m(key, oldValue);
                    this.c = i - 1;
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (oldValue != null) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(oldValue, "oldValue");
        }
    }

    public LinkedHashMap n() {
        LinkedHashMap linkedHashMap;
        synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
            Set setEntrySet = ((androidx.collection.internal.b) this.f).a.entrySet();
            Intrinsics.checkNotNullExpressionValue(setEntrySet, "<get-entries>(...)");
            linkedHashMap = new LinkedHashMap(setEntrySet.size());
            Set<Map.Entry> setEntrySet2 = ((androidx.collection.internal.b) this.f).a.entrySet();
            Intrinsics.checkNotNullExpressionValue(setEntrySet2, "<get-entries>(...)");
            for (Map.Entry entry : setEntrySet2) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        return linkedHashMap;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x007c, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void o(int r7) {
        /*
            r6 = this;
        L0:
            java.lang.Object r0 = r6.g
            com.google.mlkit.common.internal.model.a r0 = (com.google.mlkit.common.internal.model.a) r0
            monitor-enter(r0)
            int r1 = r6.c     // Catch: java.lang.Throwable -> L1b
            r2 = 1
            if (r1 < 0) goto L1f
            java.lang.Object r1 = r6.f     // Catch: java.lang.Throwable -> L1b
            androidx.collection.internal.b r1 = (androidx.collection.internal.b) r1     // Catch: java.lang.Throwable -> L1b
            java.util.LinkedHashMap r1 = r1.a     // Catch: java.lang.Throwable -> L1b
            boolean r1 = r1.isEmpty()     // Catch: java.lang.Throwable -> L1b
            if (r1 == 0) goto L1d
            int r1 = r6.c     // Catch: java.lang.Throwable -> L1b
            if (r1 != 0) goto L1f
            goto L1d
        L1b:
            r7 = move-exception
            goto L8a
        L1d:
            r1 = r2
            goto L20
        L1f:
            r1 = 0
        L20:
            if (r1 == 0) goto L7d
            int r1 = r6.c     // Catch: java.lang.Throwable -> L1b
            if (r1 <= r7) goto L7b
            java.lang.Object r1 = r6.f     // Catch: java.lang.Throwable -> L1b
            androidx.collection.internal.b r1 = (androidx.collection.internal.b) r1     // Catch: java.lang.Throwable -> L1b
            java.util.LinkedHashMap r1 = r1.a     // Catch: java.lang.Throwable -> L1b
            boolean r1 = r1.isEmpty()     // Catch: java.lang.Throwable -> L1b
            if (r1 == 0) goto L33
            goto L7b
        L33:
            java.lang.Object r1 = r6.f     // Catch: java.lang.Throwable -> L1b
            androidx.collection.internal.b r1 = (androidx.collection.internal.b) r1     // Catch: java.lang.Throwable -> L1b
            java.util.LinkedHashMap r1 = r1.a     // Catch: java.lang.Throwable -> L1b
            java.util.Set r1 = r1.entrySet()     // Catch: java.lang.Throwable -> L1b
            java.lang.String r3 = "<get-entries>(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r3)     // Catch: java.lang.Throwable -> L1b
            java.lang.Iterable r1 = (java.lang.Iterable) r1     // Catch: java.lang.Throwable -> L1b
            java.lang.Object r1 = kotlin.collections.CollectionsKt.M(r1)     // Catch: java.lang.Throwable -> L1b
            java.util.Map$Entry r1 = (java.util.Map.Entry) r1     // Catch: java.lang.Throwable -> L1b
            if (r1 != 0) goto L4e
            monitor-exit(r0)
            return
        L4e:
            java.lang.Object r3 = r1.getKey()     // Catch: java.lang.Throwable -> L1b
            java.lang.Object r1 = r1.getValue()     // Catch: java.lang.Throwable -> L1b
            java.lang.Object r4 = r6.f     // Catch: java.lang.Throwable -> L1b
            androidx.collection.internal.b r4 = (androidx.collection.internal.b) r4     // Catch: java.lang.Throwable -> L1b
            r4.getClass()     // Catch: java.lang.Throwable -> L1b
            java.lang.String r5 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r5)     // Catch: java.lang.Throwable -> L1b
            java.util.LinkedHashMap r4 = r4.a     // Catch: java.lang.Throwable -> L1b
            r4.remove(r3)     // Catch: java.lang.Throwable -> L1b
            int r4 = r6.c     // Catch: java.lang.Throwable -> L1b
            m(r3, r1)     // Catch: java.lang.Throwable -> L1b
            int r4 = r4 - r2
            r6.c = r4     // Catch: java.lang.Throwable -> L1b
            monitor-exit(r0)
            java.lang.String r0 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            java.lang.String r0 = "oldValue"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r0)
            goto L0
        L7b:
            monitor-exit(r0)
            return
        L7d:
            java.lang.String r7 = "LruCache.sizeOf() is reporting inconsistent results!"
            java.lang.String r1 = "message"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)     // Catch: java.lang.Throwable -> L1b
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L1b
            r1.<init>(r7)     // Catch: java.lang.Throwable -> L1b
            throw r1     // Catch: java.lang.Throwable -> L1b
        L8a:
            monitor-exit(r0)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0220s.o(int):void");
    }

    public String toString() {
        String str;
        switch (this.a) {
            case 0:
                synchronized (((com.google.mlkit.common.internal.model.a) this.g)) {
                    try {
                        int i = this.d;
                        int i2 = this.e + i;
                        str = "LruCache[maxSize=" + this.b + ",hits=" + this.d + ",misses=" + this.e + ",hitRate=" + (i2 != 0 ? (i * 100) / i2 : 0) + "%]";
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return str;
            default:
                return super.toString();
        }
    }

    public C0220s(StaggeredGridLayoutManager staggeredGridLayoutManager, int i) {
        this.a = 1;
        this.g = staggeredGridLayoutManager;
        this.f = new ArrayList();
        this.b = Integer.MIN_VALUE;
        this.c = Integer.MIN_VALUE;
        this.d = 0;
        this.e = i;
    }
}
