package com.google.android.gms.internal.measurement;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/* renamed from: com.google.android.gms.internal.measurement.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2977d implements Iterable, InterfaceC3027n, InterfaceC3007j {
    public final TreeMap a;
    public final TreeMap b;

    public C2977d() {
        this.a = new TreeMap();
        this.b = new TreeMap();
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final boolean M(String str) {
        return "length".equals(str) || this.b.containsKey(str);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final InterfaceC3027n a(String str) {
        InterfaceC3027n interfaceC3027n;
        return "length".equals(str) ? new C2992g(Double.valueOf(e())) : (!M(str) || (interfaceC3027n = (InterfaceC3027n) this.b.get(str)) == null) ? InterfaceC3027n.Q0 : interfaceC3027n;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final void b(String str, InterfaceC3027n interfaceC3027n) {
        TreeMap treeMap = this.b;
        if (interfaceC3027n == null) {
            treeMap.remove(str);
        } else {
            treeMap.put(str, interfaceC3027n);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:378:0x083c, code lost:
    
        if (com.google.android.gms.internal.mlkit_vision_common.AbstractC3542u3.a(r29, r31, (com.google.android.gms.internal.measurement.C3022m) r0, java.lang.Boolean.FALSE, java.lang.Boolean.TRUE).e() == e()) goto L381;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01e4  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x0274  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0284  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x0399  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x03f5  */
    /* JADX WARN: Removed duplicated region for block: B:215:0x046b  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x04fc  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x0512  */
    /* JADX WARN: Removed duplicated region for block: B:252:0x0549  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x0553  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x055d  */
    /* JADX WARN: Removed duplicated region for block: B:264:0x0596  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x05ae  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x05e2  */
    /* JADX WARN: Removed duplicated region for block: B:309:0x0692  */
    /* JADX WARN: Removed duplicated region for block: B:324:0x06d2  */
    /* JADX WARN: Removed duplicated region for block: B:350:0x0773  */
    /* JADX WARN: Removed duplicated region for block: B:359:0x07a3  */
    /* JADX WARN: Removed duplicated region for block: B:372:0x0806  */
    /* JADX WARN: Removed duplicated region for block: B:385:0x084a  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0116  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x011f  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x012c  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0158  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0171  */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.measurement.InterfaceC3027n c(java.lang.String r30, com.google.android.gms.internal.ads.C1721Kc r31, java.util.ArrayList r32) {
        /*
            Method dump skipped, instructions count: 2348
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C2977d.c(java.lang.String, com.google.android.gms.internal.ads.Kc, java.util.ArrayList):com.google.android.gms.internal.measurement.n");
    }

    public final int e() {
        TreeMap treeMap = this.a;
        if (treeMap.isEmpty()) {
            return 0;
        }
        return ((Integer) treeMap.lastKey()).intValue() + 1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C2977d)) {
            return false;
        }
        C2977d c2977d = (C2977d) obj;
        if (e() != c2977d.e()) {
            return false;
        }
        TreeMap treeMap = this.a;
        if (treeMap.isEmpty()) {
            return c2977d.a.isEmpty();
        }
        for (int iIntValue = ((Integer) treeMap.firstKey()).intValue(); iIntValue <= ((Integer) treeMap.lastKey()).intValue(); iIntValue++) {
            if (!i(iIntValue).equals(c2977d.i(iIntValue))) {
                return false;
            }
        }
        return true;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        TreeMap treeMap = this.a;
        return treeMap.size() == 1 ? i(0).g() : treeMap.size() <= 0 ? Double.valueOf(0.0d) : Double.valueOf(Double.NaN);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        return Boolean.TRUE;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }

    public final InterfaceC3027n i(int i) {
        InterfaceC3027n interfaceC3027n;
        if (i < e()) {
            return (!t(i) || (interfaceC3027n = (InterfaceC3027n) this.a.get(Integer.valueOf(i))) == null) ? InterfaceC3027n.Q0 : interfaceC3027n;
        }
        throw new IndexOutOfBoundsException("Attempting to get element outside of current array");
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new androidx.constraintlayout.core.parser.f(this);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        C2977d c2977d = new C2977d();
        for (Map.Entry entry : this.a.entrySet()) {
            boolean z = entry.getValue() instanceof InterfaceC3007j;
            TreeMap treeMap = c2977d.a;
            if (z) {
                treeMap.put((Integer) entry.getKey(), (InterfaceC3027n) entry.getValue());
            } else {
                treeMap.put((Integer) entry.getKey(), ((InterfaceC3027n) entry.getValue()).j());
            }
        }
        return c2977d;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return new C2972c(this.a.keySet().iterator(), this.b.keySet().iterator());
    }

    public final String m(String str) {
        String str2;
        StringBuilder sb = new StringBuilder();
        if (!this.a.isEmpty()) {
            int i = 0;
            while (true) {
                str2 = str == null ? "" : str;
                if (i >= e()) {
                    break;
                }
                InterfaceC3027n interfaceC3027nI = i(i);
                sb.append(str2);
                if (!(interfaceC3027nI instanceof r) && !(interfaceC3027nI instanceof C3017l)) {
                    sb.append(interfaceC3027nI.zzi());
                }
                i++;
            }
            sb.delete(0, str2.length());
        }
        return sb.toString();
    }

    public final Iterator n() {
        return this.a.keySet().iterator();
    }

    public final ArrayList o() {
        ArrayList arrayList = new ArrayList(e());
        for (int i = 0; i < e(); i++) {
            arrayList.add(i(i));
        }
        return arrayList;
    }

    public final void r(int i) {
        TreeMap treeMap = this.a;
        int iIntValue = ((Integer) treeMap.lastKey()).intValue();
        if (i > iIntValue || i < 0) {
            return;
        }
        treeMap.remove(Integer.valueOf(i));
        if (i == iIntValue) {
            int i2 = i - 1;
            Integer numValueOf = Integer.valueOf(i2);
            if (treeMap.containsKey(numValueOf) || i2 < 0) {
                return;
            }
            treeMap.put(numValueOf, InterfaceC3027n.Q0);
            return;
        }
        while (true) {
            i++;
            if (i > ((Integer) treeMap.lastKey()).intValue()) {
                return;
            }
            Integer numValueOf2 = Integer.valueOf(i);
            InterfaceC3027n interfaceC3027n = (InterfaceC3027n) treeMap.get(numValueOf2);
            if (interfaceC3027n != null) {
                treeMap.put(Integer.valueOf(i - 1), interfaceC3027n);
                treeMap.remove(numValueOf2);
            }
        }
    }

    public final void s(int i, InterfaceC3027n interfaceC3027n) {
        if (i > 32468) {
            throw new IllegalStateException("Array too large");
        }
        if (i < 0) {
            throw new IndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Out of bounds index: "));
        }
        TreeMap treeMap = this.a;
        if (interfaceC3027n == null) {
            treeMap.remove(Integer.valueOf(i));
        } else {
            treeMap.put(Integer.valueOf(i), interfaceC3027n);
        }
    }

    public final boolean t(int i) {
        if (i >= 0) {
            TreeMap treeMap = this.a;
            if (i <= ((Integer) treeMap.lastKey()).intValue()) {
                return treeMap.containsKey(Integer.valueOf(i));
            }
        }
        throw new IndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Out of bounds index: "));
    }

    public final String toString() {
        return m(",");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        return m(",");
    }

    public C2977d(List list) {
        this();
        if (list != null) {
            for (int i = 0; i < list.size(); i++) {
                s(i, (InterfaceC3027n) list.get(i));
            }
        }
    }
}
