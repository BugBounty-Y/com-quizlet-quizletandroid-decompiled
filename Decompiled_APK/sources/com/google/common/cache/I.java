package com.google.common.cache;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.Tt;
import java.util.AbstractMap;
import java.util.AbstractQueue;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class I extends AbstractMap implements ConcurrentMap {
    public static final Logger u = Logger.getLogger(I.class.getName());
    public static final C3913g v = new C3913g();
    public static final C3914h w = new C3914h();
    public final int a;
    public final int b;
    public final s[] c;
    public final int d;
    public final com.google.common.base.f e;
    public final com.google.common.base.f f;
    public final x g;
    public final x h;
    public final long i;
    public final EnumC3911e j;
    public final long k;
    public final long l;
    public final AbstractQueue m;
    public final EnumC3910d n;
    public final com.google.common.base.q o;
    public final int p;
    public final C3907a q;
    public o r;
    public Tt s;
    public o t;

    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.common.cache.I, java.util.AbstractMap] */
    public I(C3912f c3912f) {
        ?? abstractMap = new AbstractMap();
        int i = c3912f.b;
        abstractMap.d = Math.min(i == -1 ? 4 : i, 65536);
        x xVar = c3912f.f;
        u uVar = x.a;
        x xVar2 = (x) com.google.common.base.b.i(xVar, uVar);
        abstractMap.g = xVar2;
        abstractMap.h = (x) com.google.common.base.b.i(c3912f.g, uVar);
        abstractMap.e = (com.google.common.base.f) com.google.common.base.b.i(c3912f.j, ((x) com.google.common.base.b.i(c3912f.f, uVar)).a());
        abstractMap.f = (com.google.common.base.f) com.google.common.base.b.i(c3912f.k, ((x) com.google.common.base.b.i(c3912f.g, uVar)).a());
        long j = (c3912f.h == 0 || c3912f.i == 0) ? 0L : c3912f.e == null ? c3912f.c : c3912f.d;
        abstractMap.i = j;
        EnumC3911e enumC3911e = c3912f.e;
        EnumC3911e enumC3911e2 = EnumC3911e.a;
        EnumC3911e enumC3911e3 = (EnumC3911e) com.google.common.base.b.i(enumC3911e, enumC3911e2);
        abstractMap.j = enumC3911e3;
        long j2 = c3912f.i;
        abstractMap.k = j2 == -1 ? 0L : j2;
        long j3 = c3912f.h;
        abstractMap.l = j3 != -1 ? j3 : 0L;
        EnumC3910d enumC3910d = c3912f.l;
        EnumC3910d enumC3910d2 = EnumC3910d.a;
        EnumC3910d enumC3910d3 = (EnumC3910d) com.google.common.base.b.i(enumC3910d, enumC3910d2);
        abstractMap.n = enumC3910d3;
        abstractMap.m = enumC3910d3 == enumC3910d2 ? w : new ConcurrentLinkedQueue();
        int i2 = 1;
        int i3 = 0;
        boolean z = abstractMap.d() || abstractMap.b();
        com.google.common.base.q qVar = c3912f.m;
        abstractMap.o = qVar == null ? z ? com.google.common.base.q.a : C3912f.o : qVar;
        abstractMap.p = m.a[((abstractMap.b() || abstractMap.a() || abstractMap.b()) ? (char) 1 : (char) 0) | (xVar2 != x.b ? (char) 0 : (char) 4) | (abstractMap.d() || abstractMap.d() ? 2 : 0)];
        com.google.common.base.o oVar = C3912f.n;
        abstractMap.q = (C3907a) oVar.a;
        int iMin = Math.min(16, 1073741824);
        if (abstractMap.a() && enumC3911e3 == enumC3911e2) {
            iMin = (int) Math.min(iMin, j);
        }
        int i4 = 1;
        int i5 = 0;
        while (i4 < abstractMap.d && (!abstractMap.a() || i4 * 20 <= abstractMap.i)) {
            i5++;
            i4 <<= 1;
        }
        abstractMap.b = 32 - i5;
        abstractMap.a = i4 - 1;
        abstractMap.c = new s[i4];
        int i6 = iMin / i4;
        while (i2 < (i6 * i4 < iMin ? i6 + 1 : i6)) {
            i2 <<= 1;
        }
        if (abstractMap.a()) {
            long j4 = abstractMap.i;
            long j5 = i4;
            long j6 = (j4 / j5) + 1;
            long j7 = j4 % j5;
            while (true) {
                s[] sVarArr = abstractMap.c;
                if (i3 >= sVarArr.length) {
                    return;
                }
                if (i3 == j7) {
                    j6--;
                }
                long j8 = j6;
                int i7 = i2;
                sVarArr[i3] = new s(abstractMap, i7, j8, (C3907a) oVar.a);
                i3++;
                i2 = i7;
                j6 = j8;
            }
        } else {
            int i8 = i2;
            I i9 = abstractMap;
            while (true) {
                s[] sVarArr2 = i9.c;
                if (i3 >= sVarArr2.length) {
                    return;
                }
                sVarArr2[i3] = new s(i9, i8, -1L, (C3907a) oVar.a);
                i3++;
                i9 = this;
            }
        }
    }

    public final boolean a() {
        return this.i >= 0;
    }

    public final boolean b() {
        return this.k > 0;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        for (s sVar : this.c) {
            if (sVar.b != 0) {
                sVar.lock();
                try {
                    sVar.p(sVar.a.o.a());
                    AtomicReferenceArray atomicReferenceArray = sVar.f;
                    for (int i = 0; i < atomicReferenceArray.length(); i++) {
                        for (J next = (J) atomicReferenceArray.get(i); next != null; next = next.getNext()) {
                            if (next.h().a()) {
                                Object key = next.getKey();
                                Object obj = next.h().get();
                                int i2 = (key == null || obj == null) ? 3 : 1;
                                next.p();
                                sVar.d(key, next.h().c(), obj, i2);
                            }
                        }
                    }
                    for (int i3 = 0; i3 < atomicReferenceArray.length(); i3++) {
                        atomicReferenceArray.set(i3, null);
                    }
                    I i4 = sVar.a;
                    u uVar = x.a;
                    if (i4.g != uVar) {
                        while (sVar.h.poll() != null) {
                        }
                    }
                    if (i4.h != uVar) {
                        while (sVar.i.poll() != null) {
                        }
                    }
                    sVar.l.clear();
                    sVar.m.clear();
                    sVar.k.set(0);
                    sVar.d++;
                    sVar.b = 0;
                    sVar.unlock();
                    sVar.q();
                } catch (Throwable th) {
                    sVar.unlock();
                    sVar.q();
                    throw th;
                }
            }
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        if (obj == null) {
            return false;
        }
        int iE = e(obj);
        s sVarG = g(iE);
        sVarG.getClass();
        try {
            if (sVarG.b == 0) {
                return false;
            }
            J j = sVarG.j(sVarG.a.o.a(), obj, iE);
            if (j == null) {
                return false;
            }
            return j.h().get() != null;
        } finally {
            sVarG.k();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x007f A[ADDED_TO_REGION, REMOVE, SYNTHETIC] */
    @Override // java.util.AbstractMap, java.util.Map
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean containsValue(java.lang.Object r21) {
        /*
            r20 = this;
            r1 = r20
            r0 = r21
            if (r0 != 0) goto La
        L6:
            r16 = 0
            goto La4
        La:
            com.google.common.base.q r3 = r1.o
            long r3 = r3.a()
            com.google.common.cache.s[] r5 = r1.c
            r6 = -1
            r8 = 0
        L15:
            r9 = 3
            if (r8 >= r9) goto L6
            int r9 = r5.length
            r10 = 0
            r12 = 0
        L1c:
            if (r12 >= r9) goto L94
            r13 = r5[r12]
            int r14 = r13.b
            java.util.concurrent.atomic.AtomicReferenceArray r14 = r13.f
            r15 = 0
            r16 = 0
        L27:
            int r2 = r14.length()
            if (r15 >= r2) goto L8b
            java.lang.Object r2 = r14.get(r15)
            com.google.common.cache.J r2 = (com.google.common.cache.J) r2
        L33:
            if (r2 == 0) goto L86
            java.lang.Object r17 = r2.getKey()
            r18 = 0
            if (r17 != 0) goto L45
            r13.t()
        L40:
            r19 = r5
        L42:
            r5 = r18
            goto L71
        L45:
            com.google.common.cache.C r17 = r2.h()
            java.lang.Object r17 = r17.get()
            if (r17 != 0) goto L53
            r13.t()
            goto L40
        L53:
            r19 = r5
            com.google.common.cache.I r5 = r13.a
            boolean r5 = r5.f(r2, r3)
            if (r5 == 0) goto L6f
            boolean r5 = r13.tryLock()
            if (r5 == 0) goto L42
            r13.g(r3)     // Catch: java.lang.Throwable -> L6a
            r13.unlock()
            goto L42
        L6a:
            r0 = move-exception
            r13.unlock()
            throw r0
        L6f:
            r5 = r17
        L71:
            r17 = r2
            if (r5 == 0) goto L7f
            com.google.common.base.f r2 = r1.f
            boolean r2 = r2.c(r0, r5)
            if (r2 == 0) goto L7f
            r0 = 1
            return r0
        L7f:
            com.google.common.cache.J r2 = r17.getNext()
            r5 = r19
            goto L33
        L86:
            r19 = r5
            int r15 = r15 + 1
            goto L27
        L8b:
            r19 = r5
            int r2 = r13.d
            long r13 = (long) r2
            long r10 = r10 + r13
            int r12 = r12 + 1
            goto L1c
        L94:
            r19 = r5
            r16 = 0
            int r2 = (r10 > r6 ? 1 : (r10 == r6 ? 0 : -1))
            if (r2 != 0) goto L9d
            goto La4
        L9d:
            int r8 = r8 + 1
            r6 = r10
            r5 = r19
            goto L15
        La4:
            return r16
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.common.cache.I.containsValue(java.lang.Object):boolean");
    }

    public final boolean d() {
        return this.l > 0;
    }

    public final int e(Object obj) {
        int iB = this.e.b(obj);
        int i = iB + ((iB << 15) ^ (-12931));
        int i2 = i ^ (i >>> 10);
        int i3 = i2 + (i2 << 3);
        int i4 = i3 ^ (i3 >>> 6);
        int i5 = (i4 << 2) + (i4 << 14) + i4;
        return (i5 >>> 16) ^ i5;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set entrySet() {
        o oVar = this.t;
        if (oVar != null) {
            return oVar;
        }
        o oVar2 = new o(this, 0);
        this.t = oVar2;
        return oVar2;
    }

    public final boolean f(J j, long j2) {
        j.getClass();
        if (!b() || j2 - j.f() < this.k) {
            return d() && j2 - j.c() >= this.l;
        }
        return true;
    }

    public final s g(int i) {
        return this.c[(i >>> this.b) & this.a];
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        if (obj == null) {
            return null;
        }
        int iE = e(obj);
        return g(iE).h(iE, obj);
    }

    @Override // java.util.Map, java.util.concurrent.ConcurrentMap
    public final Object getOrDefault(Object obj, Object obj2) {
        Object obj3 = get(obj);
        return obj3 != null ? obj3 : obj2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean isEmpty() {
        s[] sVarArr = this.c;
        long j = 0;
        for (s sVar : sVarArr) {
            if (sVar.b != 0) {
                return false;
            }
            j += r8.d;
        }
        if (j == 0) {
            return true;
        }
        for (s sVar2 : sVarArr) {
            if (sVar2.b != 0) {
                return false;
            }
            j -= r9.d;
        }
        return j == 0;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set keySet() {
        o oVar = this.r;
        if (oVar != null) {
            return oVar;
        }
        o oVar2 = new o(this, 1);
        this.r = oVar2;
        return oVar2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        obj.getClass();
        obj2.getClass();
        int iE = e(obj);
        return g(iE).l(obj, false, obj2, iE);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void putAll(Map map) {
        for (Map.Entry entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override // java.util.Map, java.util.concurrent.ConcurrentMap
    public final Object putIfAbsent(Object obj, Object obj2) {
        obj.getClass();
        obj2.getClass();
        int iE = e(obj);
        return g(iE).l(obj, true, obj2, iE);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        int i;
        if (obj == null) {
            return null;
        }
        int iE = e(obj);
        s sVarG = g(iE);
        sVarG.lock();
        try {
            sVarG.p(sVarG.a.o.a());
            AtomicReferenceArray atomicReferenceArray = sVarG.f;
            int length = iE & (atomicReferenceArray.length() - 1);
            J j = (J) atomicReferenceArray.get(length);
            for (J next = j; next != null; next = next.getNext()) {
                Object key = next.getKey();
                if (next.p() == iE && key != null && sVarG.a.e.c(obj, key)) {
                    C cH = next.h();
                    Object obj2 = cH.get();
                    if (obj2 != null) {
                        i = 1;
                    } else {
                        if (!cH.a()) {
                            sVarG.unlock();
                            sVarG.q();
                            return null;
                        }
                        i = 3;
                    }
                    sVarG.d++;
                    J jO = sVarG.o(j, next, key, obj2, cH, i);
                    int i2 = sVarG.b - 1;
                    atomicReferenceArray.set(length, jO);
                    sVarG.b = i2;
                    sVarG.unlock();
                    sVarG.q();
                    return obj2;
                }
            }
            return null;
        } finally {
            sVarG.unlock();
            sVarG.q();
        }
    }

    @Override // java.util.Map, java.util.concurrent.ConcurrentMap
    public final Object replace(Object obj, Object obj2) {
        obj.getClass();
        obj2.getClass();
        int iE = e(obj);
        s sVarG = g(iE);
        sVarG.lock();
        try {
            long jA = sVarG.a.o.a();
            sVarG.p(jA);
            AtomicReferenceArray atomicReferenceArray = sVarG.f;
            int length = iE & (atomicReferenceArray.length() - 1);
            J j = (J) atomicReferenceArray.get(length);
            long j2 = jA;
            J next = j;
            while (next != null) {
                J j3 = j;
                Object key = next.getKey();
                if (next.p() == iE && key != null && sVarG.a.e.c(obj, key)) {
                    long j4 = j2;
                    C cH = next.h();
                    Object obj3 = cH.get();
                    if (obj3 != null) {
                        sVarG.d++;
                        sVarG.d(obj, cH.c(), obj3, 2);
                        sVarG.s(next, obj2, j4);
                        sVarG.e(next);
                        sVarG.unlock();
                        sVarG.q();
                        return obj3;
                    }
                    if (cH.a()) {
                        sVarG.d++;
                        J jO = sVarG.o(j3, next, key, obj3, cH, 3);
                        int i = sVarG.b - 1;
                        atomicReferenceArray.set(length, jO);
                        sVarG.b = i;
                    }
                    sVarG.unlock();
                    sVarG.q();
                    return null;
                }
                long j5 = j2;
                next = next.getNext();
                j = j3;
                j2 = j5;
            }
            return null;
        } finally {
            sVarG.unlock();
            sVarG.q();
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int size() {
        long jMax = 0;
        for (int i = 0; i < this.c.length; i++) {
            jMax += Math.max(0, r0[i].b);
        }
        if (jMax > 2147483647L) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (jMax < -2147483648L) {
            return Integer.MIN_VALUE;
        }
        return (int) jMax;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Collection values() {
        Tt tt = this.s;
        if (tt != null) {
            return tt;
        }
        Tt tt2 = new Tt((Object) this, 5);
        this.s = tt2;
        return tt2;
    }

    @Override // java.util.Map, java.util.concurrent.ConcurrentMap
    public final boolean remove(Object obj, Object obj2) {
        int i;
        if (obj == null || obj2 == null) {
            return false;
        }
        int iE = e(obj);
        s sVarG = g(iE);
        sVarG.lock();
        try {
            sVarG.p(sVarG.a.o.a());
            AtomicReferenceArray atomicReferenceArray = sVarG.f;
            int length = iE & (atomicReferenceArray.length() - 1);
            J j = (J) atomicReferenceArray.get(length);
            for (J next = j; next != null; next = next.getNext()) {
                Object key = next.getKey();
                if (next.p() == iE && key != null && sVarG.a.e.c(obj, key)) {
                    C cH = next.h();
                    Object obj3 = cH.get();
                    if (sVarG.a.f.c(obj2, obj3)) {
                        i = 1;
                    } else {
                        if (obj3 != null || !cH.a()) {
                            sVarG.unlock();
                            sVarG.q();
                            return false;
                        }
                        i = 3;
                    }
                    sVarG.d++;
                    J jO = sVarG.o(j, next, key, obj3, cH, i);
                    int i2 = sVarG.b - 1;
                    atomicReferenceArray.set(length, jO);
                    sVarG.b = i2;
                    return i == 1;
                }
            }
            sVarG.unlock();
            sVarG.q();
            return false;
        } finally {
            sVarG.unlock();
            sVarG.q();
        }
    }

    @Override // java.util.Map, java.util.concurrent.ConcurrentMap
    public final boolean replace(Object obj, Object obj2, Object obj3) {
        obj.getClass();
        obj3.getClass();
        boolean z = false;
        if (obj2 == null) {
            return false;
        }
        int iE = e(obj);
        s sVarG = g(iE);
        sVarG.lock();
        try {
            long jA = sVarG.a.o.a();
            sVarG.p(jA);
            AtomicReferenceArray atomicReferenceArray = sVarG.f;
            int length = iE & (atomicReferenceArray.length() - 1);
            J j = (J) atomicReferenceArray.get(length);
            long j2 = jA;
            J next = j;
            while (next != null) {
                J j3 = j;
                Object key = next.getKey();
                if (next.p() == iE && key != null && sVarG.a.e.c(obj, key)) {
                    boolean z2 = z;
                    long j4 = j2;
                    C cH = next.h();
                    Object obj4 = cH.get();
                    if (obj4 == null) {
                        if (cH.a()) {
                            sVarG.d++;
                            J jO = sVarG.o(j3, next, key, obj4, cH, 3);
                            int i = sVarG.b - 1;
                            atomicReferenceArray.set(length, jO);
                            sVarG.b = i;
                        }
                        return z2;
                    }
                    if (sVarG.a.f.c(obj2, obj4)) {
                        sVarG.d++;
                        sVarG.d(obj, cH.c(), obj4, 2);
                        sVarG.s(next, obj3, j4);
                        sVarG.e(next);
                        return true;
                    }
                    if (sVarG.a.b()) {
                        next.d(j4);
                    }
                    sVarG.m.add(next);
                    return z2;
                }
                boolean z3 = z;
                j = j3;
                long j5 = j2;
                int i2 = iE;
                next = next.getNext();
                iE = i2;
                j2 = j5;
                z = z3;
            }
            return z;
        } finally {
            sVarG.unlock();
            sVarG.q();
        }
    }
}
