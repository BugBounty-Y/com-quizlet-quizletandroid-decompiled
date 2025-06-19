package androidx.datastore.preferences.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final LinkedHashMap a;
    public final com.google.android.gms.auth.api.signin.internal.h b;

    public b(LinkedHashMap preferencesMap, boolean z) {
        Intrinsics.checkNotNullParameter(preferencesMap, "preferencesMap");
        this.a = preferencesMap;
        this.b = new com.google.android.gms.auth.api.signin.internal.h(z);
    }

    public final Map a() {
        Pair pair;
        Set<Map.Entry> setEntrySet = this.a.entrySet();
        int iA = U.a(C.q(setEntrySet, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap map = new LinkedHashMap(iA);
        for (Map.Entry entry : setEntrySet) {
            Object value = entry.getValue();
            if (value instanceof byte[]) {
                Object key = entry.getKey();
                byte[] bArr = (byte[]) value;
                byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
                Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(this, size)");
                pair = new Pair(key, bArrCopyOf);
            } else {
                pair = new Pair(entry.getKey(), entry.getValue());
            }
            map.put(pair.a, pair.b);
        }
        Intrinsics.checkNotNullParameter(map, "map");
        Map mapUnmodifiableMap = Collections.unmodifiableMap(map);
        Intrinsics.checkNotNullExpressionValue(mapUnmodifiableMap, "unmodifiableMap(map)");
        return mapUnmodifiableMap;
    }

    public final void b() {
        if (((AtomicBoolean) this.b.b).get()) {
            throw new IllegalStateException("Do mutate preferences once returned to DataStore.");
        }
    }

    public final Object c(f key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = this.a.get(key);
        if (!(obj instanceof byte[])) {
            return obj;
        }
        byte[] bArr = (byte[]) obj;
        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
        Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(this, size)");
        return bArrCopyOf;
    }

    public final void d(f key) {
        Intrinsics.checkNotNullParameter(key, "key");
        b();
        this.a.remove(key);
    }

    public final void e(f key, Object obj) {
        Intrinsics.checkNotNullParameter(key, "key");
        f(key, obj);
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean equals(java.lang.Object r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof androidx.datastore.preferences.core.b
            r1 = 0
            if (r0 != 0) goto L6
            goto L62
        L6:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.util.LinkedHashMap r0 = r7.a
            java.util.LinkedHashMap r2 = r6.a
            r3 = 1
            if (r0 != r2) goto L10
            goto L63
        L10:
            int r0 = r0.size()
            int r4 = r2.size()
            if (r0 == r4) goto L1b
            goto L62
        L1b:
            java.util.LinkedHashMap r7 = r7.a
            boolean r0 = r7.isEmpty()
            if (r0 == 0) goto L24
            goto L63
        L24:
            java.util.Set r7 = r7.entrySet()
            java.util.Iterator r7 = r7.iterator()
        L2c:
            boolean r0 = r7.hasNext()
            if (r0 == 0) goto L63
            java.lang.Object r0 = r7.next()
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0
            java.lang.Object r4 = r0.getKey()
            java.lang.Object r4 = r2.get(r4)
            if (r4 == 0) goto L5f
            java.lang.Object r0 = r0.getValue()
            boolean r5 = r0 instanceof byte[]
            if (r5 == 0) goto L5a
            boolean r5 = r4 instanceof byte[]
            if (r5 == 0) goto L5f
            byte[] r0 = (byte[]) r0
            byte[] r4 = (byte[]) r4
            boolean r0 = java.util.Arrays.equals(r0, r4)
            if (r0 == 0) goto L5f
            r0 = r3
            goto L60
        L5a:
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r0, r4)
            goto L60
        L5f:
            r0 = r1
        L60:
            if (r0 != 0) goto L2c
        L62:
            return r1
        L63:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.preferences.core.b.equals(java.lang.Object):boolean");
    }

    public final void f(f key, Object obj) {
        Intrinsics.checkNotNullParameter(key, "key");
        b();
        if (obj == null) {
            d(key);
            return;
        }
        boolean z = obj instanceof Set;
        LinkedHashMap linkedHashMap = this.a;
        if (z) {
            Set set = (Set) obj;
            Intrinsics.checkNotNullParameter(set, "set");
            Set setUnmodifiableSet = Collections.unmodifiableSet(CollectionsKt.A0(set));
            Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(set.toSet())");
            linkedHashMap.put(key, setUnmodifiableSet);
            return;
        }
        if (!(obj instanceof byte[])) {
            linkedHashMap.put(key, obj);
            return;
        }
        byte[] bArr = (byte[]) obj;
        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
        Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(this, size)");
        linkedHashMap.put(key, bArrCopyOf);
    }

    public final b g() {
        return new b(V.m(a()), false);
    }

    public final b h() {
        return new b(V.m(a()), true);
    }

    public final int hashCode() {
        Iterator it2 = this.a.entrySet().iterator();
        int iHashCode = 0;
        while (it2.hasNext()) {
            Object value = ((Map.Entry) it2.next()).getValue();
            iHashCode += value instanceof byte[] ? Arrays.hashCode((byte[]) value) : value.hashCode();
        }
        return iHashCode;
    }

    public final String toString() {
        return CollectionsKt.S(this.a.entrySet(), ",\n", "{\n", "\n}", a.a, 24);
    }

    public /* synthetic */ b(boolean z) {
        this(new LinkedHashMap(), z);
    }
}
