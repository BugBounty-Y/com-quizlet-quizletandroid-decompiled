package com.google.common.cache;

import java.lang.ref.ReferenceQueue;
import java.util.AbstractQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;

/* loaded from: classes2.dex */
public final class s extends ReentrantLock {
    public final I a;
    public volatile int b;
    public long c;
    public int d;
    public int e;
    public volatile AtomicReferenceArray f;
    public final long g;
    public final ReferenceQueue h;
    public final ReferenceQueue i;
    public final AbstractQueue j;
    public final AtomicInteger k = new AtomicInteger();
    public final AbstractQueue l;
    public final AbstractQueue m;
    public final C3907a n;

    public s(I i, int i2, long j, C3907a c3907a) {
        this.a = i;
        this.g = j;
        this.n = c3907a;
        AtomicReferenceArray atomicReferenceArray = new AtomicReferenceArray(i2);
        int length = (atomicReferenceArray.length() * 3) / 4;
        this.e = length;
        if (i.j == EnumC3911e.a && length == j) {
            this.e = length + 1;
        }
        this.f = atomicReferenceArray;
        u uVar = x.a;
        this.h = i.g != uVar ? new ReferenceQueue() : null;
        this.i = i.h != uVar ? new ReferenceQueue() : null;
        this.j = (i.b() || i.a()) ? new ConcurrentLinkedQueue() : I.w;
        this.l = i.d() ? new l(1) : I.w;
        this.m = (i.b() || i.a()) ? new l(0) : I.w;
    }

    public final J a(J j, J j2) {
        J jB;
        J jB2;
        Object key = j.getKey();
        if (key == null) {
            return null;
        }
        C cH = j.h();
        Object obj = cH.get();
        if (obj == null && cH.a()) {
            return null;
        }
        int i = this.a.p;
        if (i == 2) {
            jB = m.b(2, this, j, j2, key);
            m.a(j, jB);
        } else if (i == 3) {
            jB = m.b(3, this, j, j2, key);
            m.c(j, jB);
        } else if (i == 4) {
            jB = m.b(4, this, j, j2, key);
            m.a(j, jB);
            m.c(j, jB);
        } else if (i == 6) {
            jB = m.b(6, this, j, j2, key);
            m.a(j, jB);
        } else if (i == 7) {
            jB = m.b(7, this, j, j2, key);
            m.c(j, jB);
        } else {
            if (i != 8) {
                jB2 = m.b(i, this, j, j2, key);
                jB2.b(cH.e(this.i, obj, jB2));
                return jB2;
            }
            jB = m.b(8, this, j, j2, key);
            m.a(j, jB);
            m.c(j, jB);
        }
        jB2 = jB;
        jB2.b(cH.e(this.i, obj, jB2));
        return jB2;
    }

    public final void b() {
        while (true) {
            J j = (J) this.j.poll();
            if (j == null) {
                return;
            }
            AbstractQueue abstractQueue = this.m;
            if (abstractQueue.contains(j)) {
                abstractQueue.add(j);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0043, code lost:
    
        r5.d++;
        r6 = r5.o(r7, r7, r7.getKey(), r7.h().get(), r7.h(), 3);
        r7 = r5.b - 1;
        r12.set(r13, r6);
        r5.b = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00f7, code lost:
    
        r5.q();
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 299
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.common.cache.s.c():void");
    }

    public final void d(Object obj, int i, Object obj2, int i2) {
        this.c -= i;
        boolean z = false;
        if (i2 != 1 && i2 != 2) {
            z = true;
        }
        if (z) {
            this.n.getClass();
        }
        I i3 = this.a;
        if (i3.m != I.w) {
            i3.m.offer(new K(obj, obj2));
        }
    }

    public final void e(J j) {
        if (this.a.a()) {
            b();
            long jC = j.h().c();
            long j2 = this.g;
            if (jC > j2 && !n(j, j.p(), 5)) {
                throw new AssertionError();
            }
            while (this.c > j2) {
                for (J j3 : this.m) {
                    if (j3.h().c() > 0) {
                        if (!n(j3, j3.p(), 5)) {
                            throw new AssertionError();
                        }
                    }
                }
                throw new AssertionError();
            }
        }
    }

    public final void f() {
        AtomicReferenceArray atomicReferenceArray = this.f;
        int length = atomicReferenceArray.length();
        if (length >= 1073741824) {
            return;
        }
        int i = this.b;
        AtomicReferenceArray atomicReferenceArray2 = new AtomicReferenceArray(length << 1);
        this.e = (atomicReferenceArray2.length() * 3) / 4;
        int length2 = atomicReferenceArray2.length() - 1;
        for (int i2 = 0; i2 < length; i2++) {
            J next = (J) atomicReferenceArray.get(i2);
            if (next != null) {
                J next2 = next.getNext();
                int iP = next.p() & length2;
                if (next2 == null) {
                    atomicReferenceArray2.set(iP, next);
                } else {
                    J j = next;
                    while (next2 != null) {
                        int iP2 = next2.p() & length2;
                        if (iP2 != iP) {
                            j = next2;
                            iP = iP2;
                        }
                        next2 = next2.getNext();
                    }
                    atomicReferenceArray2.set(iP, j);
                    while (next != j) {
                        int iP3 = next.p() & length2;
                        J jA = a(next, (J) atomicReferenceArray2.get(iP3));
                        if (jA != null) {
                            atomicReferenceArray2.set(iP3, jA);
                        } else {
                            m(next);
                            i--;
                        }
                        next = next.getNext();
                    }
                }
            }
        }
        this.f = atomicReferenceArray2;
        this.b = i;
    }

    public final void g(long j) {
        J j2;
        J j3;
        b();
        do {
            j2 = (J) this.l.peek();
            I i = this.a;
            if (j2 == null || !i.f(j2, j)) {
                do {
                    j3 = (J) this.m.peek();
                    if (j3 == null || !i.f(j3, j)) {
                        return;
                    }
                } while (n(j3, j3.p(), 4));
                throw new AssertionError();
            }
        } while (n(j2, j2.p(), 4));
        throw new AssertionError();
    }

    public final Object h(int i, Object obj) {
        try {
            if (this.b != 0) {
                long jA = this.a.o.a();
                J j = j(jA, obj, i);
                if (j == null) {
                    return null;
                }
                Object obj2 = j.h().get();
                if (obj2 != null) {
                    if (this.a.b()) {
                        j.d(jA);
                    }
                    this.j.add(j);
                    j.getKey();
                    this.a.getClass();
                    this.a.getClass();
                    return obj2;
                }
                t();
            }
            return null;
        } finally {
            k();
        }
    }

    public final J j(long j, Object obj, int i) {
        J next = (J) this.f.get((r0.length() - 1) & i);
        while (true) {
            if (next == null) {
                next = null;
                break;
            }
            if (next.p() == i) {
                Object key = next.getKey();
                if (key == null) {
                    t();
                } else if (this.a.e.c(obj, key)) {
                    break;
                }
            }
            next = next.getNext();
        }
        if (next != null) {
            if (!this.a.f(next, j)) {
                return next;
            }
            if (tryLock()) {
                try {
                    g(j);
                    return null;
                } finally {
                    unlock();
                }
            }
        }
        return null;
    }

    public final void k() {
        if ((this.k.incrementAndGet() & 63) == 0) {
            p(this.a.o.a());
            q();
        }
    }

    public final Object l(Object obj, boolean z, Object obj2, int i) {
        int i2;
        lock();
        try {
            long jA = this.a.o.a();
            p(jA);
            if (this.b + 1 > this.e) {
                f();
            }
            AtomicReferenceArray atomicReferenceArray = this.f;
            int length = (atomicReferenceArray.length() - 1) & i;
            J j = (J) atomicReferenceArray.get(length);
            for (J next = j; next != null; next = next.getNext()) {
                Object key = next.getKey();
                if (next.p() == i && key != null && this.a.e.c(obj, key)) {
                    C cH = next.h();
                    Object obj3 = cH.get();
                    if (obj3 == null) {
                        this.d++;
                        if (cH.a()) {
                            d(obj, cH.c(), obj3, 3);
                            s(next, obj2, jA);
                            i2 = this.b;
                        } else {
                            s(next, obj2, jA);
                            i2 = this.b + 1;
                        }
                        this.b = i2;
                        e(next);
                        unlock();
                        q();
                        return null;
                    }
                    if (z) {
                        if (this.a.b()) {
                            next.d(jA);
                        }
                        this.m.add(next);
                        unlock();
                        q();
                        return obj3;
                    }
                    this.d++;
                    d(obj, cH.c(), obj3, 2);
                    s(next, obj2, jA);
                    e(next);
                    unlock();
                    q();
                    return obj3;
                }
            }
            this.d++;
            J jD = m.d(this.a.p, this, obj, i, j);
            s(jD, obj2, jA);
            atomicReferenceArray.set(length, jD);
            this.b++;
            e(jD);
            unlock();
            q();
            return null;
        } catch (Throwable th) {
            unlock();
            q();
            throw th;
        }
    }

    public final void m(J j) {
        Object key = j.getKey();
        j.p();
        d(key, j.h().c(), j.h().get(), 3);
        this.l.remove(j);
        this.m.remove(j);
    }

    public final boolean n(J j, int i, int i2) {
        AtomicReferenceArray atomicReferenceArray = this.f;
        int length = i & (atomicReferenceArray.length() - 1);
        J j2 = (J) atomicReferenceArray.get(length);
        for (J next = j2; next != null; next = next.getNext()) {
            if (next == j) {
                this.d++;
                J jO = o(j2, next, next.getKey(), next.h().get(), next.h(), i2);
                int i3 = this.b - 1;
                atomicReferenceArray.set(length, jO);
                this.b = i3;
                return true;
            }
        }
        return false;
    }

    public final J o(J j, J j2, Object obj, Object obj2, C c, int i) {
        d(obj, c.c(), obj2, i);
        this.l.remove(j2);
        this.m.remove(j2);
        if (c.d()) {
            c.b(null);
            return j;
        }
        int i2 = this.b;
        J next = j2.getNext();
        while (j != j2) {
            J jA = a(j, next);
            if (jA != null) {
                next = jA;
            } else {
                m(j);
                i2--;
            }
            j = j.getNext();
        }
        this.b = i2;
        return next;
    }

    public final void p(long j) {
        if (tryLock()) {
            try {
                c();
                g(j);
                this.k.set(0);
            } finally {
                unlock();
            }
        }
    }

    public final void q() {
        if (isHeldByCurrentThread()) {
            return;
        }
        while (true) {
            I i = this.a;
            if (((K) i.m.poll()) == null) {
                return;
            }
            try {
                i.n.getClass();
            } catch (Throwable th) {
                I.u.log(Level.WARNING, "Exception thrown by removal listener", th);
            }
        }
    }

    public final void s(J j, Object obj, long j2) {
        C cH = j.h();
        I i = this.a;
        i.j.getClass();
        j.b(i.h.b(this, j, obj));
        b();
        this.c++;
        if (i.b()) {
            j.d(j2);
        }
        if (i.d()) {
            j.g(j2);
        }
        this.m.add(j);
        this.l.add(j);
        cH.b(obj);
    }

    public final void t() {
        if (tryLock()) {
            try {
                c();
            } finally {
                unlock();
            }
        }
    }
}
