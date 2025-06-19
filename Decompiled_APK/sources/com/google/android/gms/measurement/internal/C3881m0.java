package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.EnumMap;
import java.util.Iterator;

/* renamed from: com.google.android.gms.measurement.internal.m0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3881m0 {
    public static final C3881m0 c = new C3881m0(100);
    public final EnumMap a;
    public final int b;

    public C3881m0(int i) {
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        this.a = enumMap;
        EnumC3879l0 enumC3879l0 = EnumC3879l0.AD_STORAGE;
        EnumC3875j0 enumC3875j0 = EnumC3875j0.UNINITIALIZED;
        enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) enumC3875j0);
        enumMap.put((EnumMap) EnumC3879l0.ANALYTICS_STORAGE, (EnumC3879l0) enumC3875j0);
        this.b = i;
    }

    public static char a(EnumC3875j0 enumC3875j0) {
        if (enumC3875j0 == null) {
            return '-';
        }
        int iOrdinal = enumC3875j0.ordinal();
        if (iOrdinal == 1) {
            return '+';
        }
        if (iOrdinal != 2) {
            return iOrdinal != 3 ? '-' : '1';
        }
        return '0';
    }

    public static EnumC3875j0 b(String str) {
        EnumC3875j0 enumC3875j0 = EnumC3875j0.UNINITIALIZED;
        return str == null ? enumC3875j0 : str.equals("granted") ? EnumC3875j0.GRANTED : str.equals("denied") ? EnumC3875j0.DENIED : enumC3875j0;
    }

    public static EnumC3875j0 c(char c2) {
        return c2 != '+' ? c2 != '0' ? c2 != '1' ? EnumC3875j0.UNINITIALIZED : EnumC3875j0.GRANTED : EnumC3875j0.DENIED : EnumC3875j0.POLICY;
    }

    public static C3881m0 d(int i, Bundle bundle) {
        if (bundle == null) {
            return new C3881m0(i);
        }
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.STORAGE.a) {
            enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) b(bundle.getString(enumC3879l0.a)));
        }
        return new C3881m0(enumMap, i);
    }

    public static C3881m0 e(int i, String str) {
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        EnumC3877k0 enumC3877k0 = EnumC3877k0.STORAGE;
        int i2 = 0;
        while (true) {
            EnumC3879l0[] enumC3879l0Arr = enumC3877k0.a;
            if (i2 >= enumC3879l0Arr.length) {
                return new C3881m0(enumMap, i);
            }
            String str2 = str == null ? "" : str;
            EnumC3879l0 enumC3879l0 = enumC3879l0Arr[i2];
            int i3 = i2 + 2;
            if (i3 < str2.length()) {
                enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) c(str2.charAt(i3)));
            } else {
                enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) EnumC3875j0.UNINITIALIZED);
            }
            i2++;
        }
    }

    public static String h(int i) {
        return i != -30 ? i != -20 ? i != -10 ? i != 0 ? i != 30 ? i != 90 ? i != 100 ? "OTHER" : "UNKNOWN" : "REMOTE_CONFIG" : "1P_INIT" : "1P_API" : "MANIFEST" : "API" : "TCF";
    }

    public static boolean l(int i, int i2) {
        int i3 = -30;
        if (i == -20) {
            if (i2 == -30) {
                return true;
            }
            i = -20;
        }
        if (i != -30) {
            i3 = i;
        } else if (i2 == -20) {
            return true;
        }
        return i3 == i2 || i < i2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C3881m0)) {
            return false;
        }
        C3881m0 c3881m0 = (C3881m0) obj;
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.STORAGE.a) {
            if (this.a.get(enumC3879l0) != c3881m0.a.get(enumC3879l0)) {
                return false;
            }
        }
        return this.b == c3881m0.b;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0031  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.C3881m0 f(com.google.android.gms.measurement.internal.C3881m0 r9) {
        /*
            r8 = this;
            java.util.EnumMap r0 = new java.util.EnumMap
            java.lang.Class<com.google.android.gms.measurement.internal.l0> r1 = com.google.android.gms.measurement.internal.EnumC3879l0.class
            r0.<init>(r1)
            com.google.android.gms.measurement.internal.k0 r1 = com.google.android.gms.measurement.internal.EnumC3877k0.STORAGE
            com.google.android.gms.measurement.internal.l0[] r1 = r1.a
            int r2 = r1.length
            r3 = 0
        Ld:
            if (r3 >= r2) goto L48
            r4 = r1[r3]
            java.util.EnumMap r5 = r8.a
            java.lang.Object r5 = r5.get(r4)
            com.google.android.gms.measurement.internal.j0 r5 = (com.google.android.gms.measurement.internal.EnumC3875j0) r5
            java.util.EnumMap r6 = r9.a
            java.lang.Object r6 = r6.get(r4)
            com.google.android.gms.measurement.internal.j0 r6 = (com.google.android.gms.measurement.internal.EnumC3875j0) r6
            if (r5 != 0) goto L24
            goto L31
        L24:
            if (r6 == 0) goto L40
            com.google.android.gms.measurement.internal.j0 r7 = com.google.android.gms.measurement.internal.EnumC3875j0.UNINITIALIZED
            if (r5 != r7) goto L2b
            goto L31
        L2b:
            if (r6 == r7) goto L40
            com.google.android.gms.measurement.internal.j0 r7 = com.google.android.gms.measurement.internal.EnumC3875j0.POLICY
            if (r5 != r7) goto L33
        L31:
            r5 = r6
            goto L40
        L33:
            if (r6 == r7) goto L40
            com.google.android.gms.measurement.internal.j0 r7 = com.google.android.gms.measurement.internal.EnumC3875j0.DENIED
            if (r5 == r7) goto L3f
            if (r6 != r7) goto L3c
            goto L3f
        L3c:
            com.google.android.gms.measurement.internal.j0 r5 = com.google.android.gms.measurement.internal.EnumC3875j0.GRANTED
            goto L40
        L3f:
            r5 = r7
        L40:
            if (r5 == 0) goto L45
            r0.put(r4, r5)
        L45:
            int r3 = r3 + 1
            goto Ld
        L48:
            com.google.android.gms.measurement.internal.m0 r9 = new com.google.android.gms.measurement.internal.m0
            r1 = 100
            r9.<init>(r0, r1)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3881m0.f(com.google.android.gms.measurement.internal.m0):com.google.android.gms.measurement.internal.m0");
    }

    public final C3881m0 g(C3881m0 c3881m0) {
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.STORAGE.a) {
            EnumC3875j0 enumC3875j0 = (EnumC3875j0) this.a.get(enumC3879l0);
            if (enumC3875j0 == EnumC3875j0.UNINITIALIZED) {
                enumC3875j0 = (EnumC3875j0) c3881m0.a.get(enumC3879l0);
            }
            if (enumC3875j0 != null) {
                enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) enumC3875j0);
            }
        }
        return new C3881m0(enumMap, this.b);
    }

    public final int hashCode() {
        Iterator it2 = this.a.values().iterator();
        int iHashCode = this.b * 17;
        while (it2.hasNext()) {
            iHashCode = (iHashCode * 31) + ((EnumC3875j0) it2.next()).hashCode();
        }
        return iHashCode;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0030  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String i() {
        /*
            r7 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "G1"
            r0.<init>(r1)
            com.google.android.gms.measurement.internal.k0 r1 = com.google.android.gms.measurement.internal.EnumC3877k0.STORAGE
            com.google.android.gms.measurement.internal.l0[] r1 = r1.a
            int r2 = r1.length
            r3 = 0
        Ld:
            if (r3 >= r2) goto L38
            r4 = r1[r3]
            java.util.EnumMap r5 = r7.a
            java.lang.Object r4 = r5.get(r4)
            com.google.android.gms.measurement.internal.j0 r4 = (com.google.android.gms.measurement.internal.EnumC3875j0) r4
            r5 = 45
            if (r4 == 0) goto L32
            int r4 = r4.ordinal()
            if (r4 == 0) goto L32
            r6 = 1
            if (r4 == r6) goto L30
            r6 = 2
            if (r4 == r6) goto L2d
            r6 = 3
            if (r4 == r6) goto L30
            goto L32
        L2d:
            r5 = 48
            goto L32
        L30:
            r5 = 49
        L32:
            r0.append(r5)
            int r3 = r3 + 1
            goto Ld
        L38:
            java.lang.String r0 = r0.toString()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3881m0.i():java.lang.String");
    }

    public final String j() {
        StringBuilder sb = new StringBuilder("G1");
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.STORAGE.a) {
            sb.append(a((EnumC3875j0) this.a.get(enumC3879l0)));
        }
        return sb.toString();
    }

    public final boolean k(EnumC3879l0 enumC3879l0) {
        return ((EnumC3875j0) this.a.get(enumC3879l0)) != EnumC3875j0.DENIED;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("source=");
        sb.append(h(this.b));
        for (EnumC3879l0 enumC3879l0 : EnumC3877k0.STORAGE.a) {
            sb.append(",");
            sb.append(enumC3879l0.a);
            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
            EnumC3875j0 enumC3875j0 = (EnumC3875j0) this.a.get(enumC3879l0);
            if (enumC3875j0 == null) {
                enumC3875j0 = EnumC3875j0.UNINITIALIZED;
            }
            sb.append(enumC3875j0);
        }
        return sb.toString();
    }

    public C3881m0(EnumMap enumMap, int i) {
        EnumMap enumMap2 = new EnumMap(EnumC3879l0.class);
        this.a = enumMap2;
        enumMap2.putAll(enumMap);
        this.b = i;
    }
}
