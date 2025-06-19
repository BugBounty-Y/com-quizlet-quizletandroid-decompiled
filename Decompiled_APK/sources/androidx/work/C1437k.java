package androidx.work;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1437k {
    public static final C1437k b;
    public final HashMap a;

    static {
        C1437k c1437k = new C1437k(new LinkedHashMap());
        AbstractC3390s2.d(c1437k);
        b = c1437k;
    }

    public C1437k(C1437k other) {
        Intrinsics.checkNotNullParameter(other, "other");
        this.a = new HashMap(other.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.work.C1437k a(byte[] r7) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 231
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.C1437k.a(byte[]):androidx.work.k");
    }

    public final long b(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = this.a.get(key);
        return ((Number) (obj instanceof Long ? obj : -1L)).longValue();
    }

    public final String c(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = this.a.get(key);
        if (obj instanceof String) {
            return (String) obj;
        }
        return null;
    }

    public final boolean d(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(String.class, "klass");
        Object obj = this.a.get(key);
        return obj != null && String.class.isAssignableFrom(obj.getClass());
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0059  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean equals(java.lang.Object r9) {
        /*
            r8 = this;
            r0 = 1
            if (r8 != r9) goto L5
            goto L66
        L5:
            r1 = 0
            if (r9 == 0) goto L67
            java.lang.Class r2 = r9.getClass()
            java.lang.Class<androidx.work.k> r3 = androidx.work.C1437k.class
            boolean r2 = r3.equals(r2)
            if (r2 != 0) goto L15
            goto L67
        L15:
            androidx.work.k r9 = (androidx.work.C1437k) r9
            java.util.HashMap r2 = r8.a
            java.util.Set r3 = r2.keySet()
            java.util.HashMap r9 = r9.a
            java.util.Set r4 = r9.keySet()
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            if (r4 != 0) goto L2a
            goto L67
        L2a:
            java.util.Iterator r3 = r3.iterator()
        L2e:
            boolean r4 = r3.hasNext()
            if (r4 == 0) goto L66
            java.lang.Object r4 = r3.next()
            java.lang.String r4 = (java.lang.String) r4
            java.lang.Object r5 = r2.get(r4)
            java.lang.Object r4 = r9.get(r4)
            if (r5 == 0) goto L5e
            if (r4 != 0) goto L47
            goto L5e
        L47:
            boolean r6 = r5 instanceof java.lang.Object[]
            if (r6 == 0) goto L59
            r6 = r5
            java.lang.Object[] r6 = (java.lang.Object[]) r6
            boolean r7 = r4 instanceof java.lang.Object[]
            if (r7 == 0) goto L59
            java.lang.Object[] r4 = (java.lang.Object[]) r4
            boolean r4 = kotlin.collections.C4929u.b(r6, r4)
            goto L63
        L59:
            boolean r4 = r5.equals(r4)
            goto L63
        L5e:
            if (r5 != r4) goto L62
            r4 = r0
            goto L63
        L62:
            r4 = r1
        L63:
            if (r4 != 0) goto L2e
            goto L67
        L66:
            return r0
        L67:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.C1437k.equals(java.lang.Object):boolean");
    }

    public final int hashCode() {
        int iHashCode = 0;
        for (Map.Entry entry : this.a.entrySet()) {
            Object value = entry.getValue();
            iHashCode += value instanceof Object[] ? Objects.hashCode(entry.getKey()) ^ Arrays.deepHashCode((Object[]) value) : entry.hashCode();
        }
        return iHashCode * 31;
    }

    public final String toString() {
        String str = "Data {" + CollectionsKt.S(this.a.entrySet(), null, null, null, C1436j.a, 31) + "}";
        Intrinsics.checkNotNullExpressionValue(str, "StringBuilder().apply(builderAction).toString()");
        return str;
    }

    public C1437k(LinkedHashMap values) {
        Intrinsics.checkNotNullParameter(values, "values");
        this.a = new HashMap(values);
    }
}
