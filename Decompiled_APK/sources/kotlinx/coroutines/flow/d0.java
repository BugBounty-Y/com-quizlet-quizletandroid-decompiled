package kotlinx.coroutines.flow;

import com.android.billingclient.api.C1472a;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5022i;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.flow.internal.AbstractC4993a;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.AbstractC4995c;

/* loaded from: classes3.dex */
public class d0 extends AbstractC4993a implements W, InterfaceC4992i, kotlinx.coroutines.flow.internal.z {
    public final int e;
    public final int f;
    public final kotlinx.coroutines.channels.a g;
    public Object[] h;
    public long i;
    public long j;
    public int k;
    public int l;

    public d0(int i, int i2, kotlinx.coroutines.channels.a aVar) {
        this.e = i;
        this.f = i2;
        this.g = aVar;
    }

    /* JADX WARN: Code restructure failed: missing block: B:51:0x00bc, code lost:
    
        throw r2.y();
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m(kotlinx.coroutines.flow.d0 r8, kotlinx.coroutines.flow.InterfaceC5002j r9, kotlin.coroutines.h r10) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 210
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.d0.m(kotlinx.coroutines.flow.d0, kotlinx.coroutines.flow.j, kotlin.coroutines.h):void");
    }

    @Override // kotlinx.coroutines.flow.a0
    public final List a() {
        synchronized (this) {
            int iQ = (int) ((q() + this.k) - this.i);
            if (iQ == 0) {
                return kotlin.collections.K.a;
            }
            ArrayList arrayList = new ArrayList(iQ);
            Object[] objArr = this.h;
            Intrinsics.d(objArr);
            for (int i = 0; i < iQ; i++) {
                arrayList.add(objArr[((int) (this.i + i)) & (objArr.length - 1)]);
            }
            return arrayList;
        }
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) throws Throwable {
        m(this, interfaceC5002j, hVar);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlinx.coroutines.flow.internal.z
    public final InterfaceC4992i c(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return e0.t(this, coroutineContext, i, aVar);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4993a
    public final AbstractC4995c e() {
        f0 f0Var = new f0();
        f0Var.a = -1L;
        return f0Var;
    }

    @Override // kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h frame) throws Throwable {
        Throwable th;
        kotlin.coroutines.h[] hVarArrP;
        b0 b0Var;
        if (h(obj)) {
            return Unit.a;
        }
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        kotlin.coroutines.h[] hVarArrP2 = AbstractC4994b.a;
        synchronized (this) {
            try {
                if (s(obj)) {
                    try {
                        kotlin.p pVar = kotlin.r.b;
                        c5028l.resumeWith(Unit.a);
                        hVarArrP = p(hVarArrP2);
                        b0Var = null;
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                } else {
                    try {
                        b0Var = new b0(this, q() + this.k + this.l, obj, c5028l);
                        o(b0Var);
                        this.l++;
                        if (this.f == 0) {
                            hVarArrP2 = p(hVarArrP2);
                        }
                        hVarArrP = hVarArrP2;
                    } catch (Throwable th3) {
                        th = th3;
                        th = th;
                        throw th;
                    }
                }
                if (b0Var != null) {
                    c5028l.v(new C5022i(b0Var, 2));
                }
                for (kotlin.coroutines.h hVar : hVarArrP) {
                    if (hVar != null) {
                        kotlin.p pVar2 = kotlin.r.b;
                        hVar.resumeWith(Unit.a);
                    }
                }
                Object objQ = c5028l.q();
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                if (objQ == aVar) {
                    Intrinsics.checkNotNullParameter(frame, "frame");
                }
                if (objQ != aVar) {
                    objQ = Unit.a;
                }
                return objQ == aVar ? objQ : Unit.a;
            } catch (Throwable th4) {
                th = th4;
            }
        }
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4993a
    public final AbstractC4995c[] f() {
        return new f0[2];
    }

    @Override // kotlinx.coroutines.flow.W
    public final void g() throws Throwable {
        synchronized (this) {
            try {
                try {
                    v(q() + this.k, this.j, q() + this.k, q() + this.k + this.l);
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    @Override // kotlinx.coroutines.flow.W
    public final boolean h(Object obj) {
        int i;
        boolean z;
        kotlin.coroutines.h[] hVarArrP = AbstractC4994b.a;
        synchronized (this) {
            if (s(obj)) {
                hVarArrP = p(hVarArrP);
                z = true;
            } else {
                z = false;
            }
        }
        for (kotlin.coroutines.h hVar : hVarArrP) {
            if (hVar != null) {
                kotlin.p pVar = kotlin.r.b;
                hVar.resumeWith(Unit.a);
            }
        }
        return z;
    }

    public final Object k(f0 f0Var, c0 frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        synchronized (this) {
            if (t(f0Var) < 0) {
                f0Var.b = c5028l;
            } else {
                kotlin.p pVar = kotlin.r.b;
                c5028l.resumeWith(Unit.a);
            }
            Unit unit = Unit.a;
        }
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    public final void l() {
        if (this.f != 0 || this.l > 1) {
            Object[] objArr = this.h;
            Intrinsics.d(objArr);
            while (this.l > 0) {
                long jQ = q();
                int i = this.k;
                int i2 = this.l;
                if (objArr[((int) ((jQ + (i + i2)) - 1)) & (objArr.length - 1)] != e0.a) {
                    return;
                }
                this.l = i2 - 1;
                e0.e(objArr, q() + this.k + this.l, null);
            }
        }
    }

    public final void n() {
        AbstractC4995c[] abstractC4995cArr;
        Object[] objArr = this.h;
        Intrinsics.d(objArr);
        e0.e(objArr, q(), null);
        this.k--;
        long jQ = q() + 1;
        if (this.i < jQ) {
            this.i = jQ;
        }
        if (this.j < jQ) {
            if (this.b != 0 && (abstractC4995cArr = this.a) != null) {
                for (AbstractC4995c abstractC4995c : abstractC4995cArr) {
                    if (abstractC4995c != null) {
                        f0 f0Var = (f0) abstractC4995c;
                        long j = f0Var.a;
                        if (j >= 0 && j < jQ) {
                            f0Var.a = jQ;
                        }
                    }
                }
            }
            this.j = jQ;
        }
    }

    public final void o(Object obj) {
        int i = this.k + this.l;
        Object[] objArrR = this.h;
        if (objArrR == null) {
            objArrR = r(0, 2, null);
        } else if (i >= objArrR.length) {
            objArrR = r(i, objArrR.length * 2, objArrR);
        }
        e0.e(objArrR, q() + i, obj);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v6, types: [java.lang.Object, java.lang.Object[]] */
    public final kotlin.coroutines.h[] p(kotlin.coroutines.h[] hVarArr) {
        AbstractC4995c[] abstractC4995cArr;
        f0 f0Var;
        C5028l c5028l;
        int length = hVarArr.length;
        if (this.b != 0 && (abstractC4995cArr = this.a) != null) {
            int length2 = abstractC4995cArr.length;
            int i = 0;
            hVarArr = hVarArr;
            while (i < length2) {
                AbstractC4995c abstractC4995c = abstractC4995cArr[i];
                if (abstractC4995c != null && (c5028l = (f0Var = (f0) abstractC4995c).b) != null && t(f0Var) >= 0) {
                    int length3 = hVarArr.length;
                    hVarArr = hVarArr;
                    if (length >= length3) {
                        ?? CopyOf = Arrays.copyOf(hVarArr, Math.max(2, hVarArr.length * 2));
                        Intrinsics.checkNotNullExpressionValue(CopyOf, "copyOf(...)");
                        hVarArr = CopyOf;
                    }
                    hVarArr[length] = c5028l;
                    f0Var.b = null;
                    length++;
                }
                i++;
                hVarArr = hVarArr;
            }
        }
        return hVarArr;
    }

    public final long q() {
        return Math.min(this.j, this.i);
    }

    public final Object[] r(int i, int i2, Object[] objArr) {
        if (i2 <= 0) {
            throw new IllegalStateException("Buffer size overflow");
        }
        Object[] objArr2 = new Object[i2];
        this.h = objArr2;
        if (objArr != null) {
            long jQ = q();
            for (int i3 = 0; i3 < i; i3++) {
                long j = i3 + jQ;
                e0.e(objArr2, j, objArr[((int) j) & (objArr.length - 1)]);
            }
        }
        return objArr2;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0047  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean s(java.lang.Object r13) {
        /*
            r12 = this;
            int r1 = r12.b
            int r2 = r12.e
            r9 = 1
            if (r1 != 0) goto L23
            if (r2 != 0) goto Lb
            goto L7f
        Lb:
            r12.o(r13)
            int r1 = r12.k
            int r1 = r1 + r9
            r12.k = r1
            if (r1 <= r2) goto L18
            r12.n()
        L18:
            long r1 = r12.q()
            int r3 = r12.k
            long r3 = (long) r3
            long r1 = r1 + r3
            r12.j = r1
            return r9
        L23:
            int r1 = r12.k
            int r3 = r12.f
            if (r1 < r3) goto L47
            long r4 = r12.j
            long r6 = r12.i
            int r1 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r1 > 0) goto L47
            kotlinx.coroutines.channels.a r1 = r12.g
            int r1 = r1.ordinal()
            if (r1 == 0) goto L45
            if (r1 == r9) goto L47
            r2 = 2
            if (r1 != r2) goto L3f
            goto L7f
        L3f:
            kotlin.NoWhenBranchMatchedException r1 = new kotlin.NoWhenBranchMatchedException
            r1.<init>()
            throw r1
        L45:
            r1 = 0
            return r1
        L47:
            r12.o(r13)
            int r1 = r12.k
            int r1 = r1 + r9
            r12.k = r1
            if (r1 <= r3) goto L54
            r12.n()
        L54:
            long r3 = r12.q()
            int r1 = r12.k
            long r5 = (long) r1
            long r3 = r3 + r5
            long r5 = r12.i
            long r3 = r3 - r5
            int r1 = (int) r3
            if (r1 <= r2) goto L7f
            r1 = 1
            long r1 = r1 + r5
            long r3 = r12.j
            long r5 = r12.q()
            int r7 = r12.k
            long r7 = (long) r7
            long r5 = r5 + r7
            long r7 = r12.q()
            int r10 = r12.k
            long r10 = (long) r10
            long r7 = r7 + r10
            int r10 = r12.l
            long r10 = (long) r10
            long r7 = r7 + r10
            r0 = r12
            r0.v(r1, r3, r5, r7)
        L7f:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.d0.s(java.lang.Object):boolean");
    }

    public final long t(f0 f0Var) {
        long j = f0Var.a;
        if (j < q() + this.k) {
            return j;
        }
        if (this.f <= 0 && j <= q() && this.l != 0) {
            return j;
        }
        return -1L;
    }

    public final Object u(f0 f0Var) {
        Object obj;
        kotlin.coroutines.h[] hVarArrW = AbstractC4994b.a;
        synchronized (this) {
            try {
                long jT = t(f0Var);
                if (jT < 0) {
                    obj = e0.a;
                } else {
                    long j = f0Var.a;
                    Object[] objArr = this.h;
                    Intrinsics.d(objArr);
                    Object obj2 = objArr[((int) jT) & (objArr.length - 1)];
                    if (obj2 instanceof b0) {
                        obj2 = ((b0) obj2).c;
                    }
                    f0Var.a = jT + 1;
                    Object obj3 = obj2;
                    hVarArrW = w(j);
                    obj = obj3;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        for (kotlin.coroutines.h hVar : hVarArrW) {
            if (hVar != null) {
                kotlin.p pVar = kotlin.r.b;
                hVar.resumeWith(Unit.a);
            }
        }
        return obj;
    }

    public final void v(long j, long j2, long j3, long j4) {
        long jMin = Math.min(j2, j);
        for (long jQ = q(); jQ < jMin; jQ++) {
            Object[] objArr = this.h;
            Intrinsics.d(objArr);
            e0.e(objArr, jQ, null);
        }
        this.i = j;
        this.j = j2;
        this.k = (int) (j3 - jMin);
        this.l = (int) (j4 - j3);
    }

    public final kotlin.coroutines.h[] w(long j) {
        long j2;
        long j3;
        long j4;
        int i;
        kotlin.coroutines.h[] hVarArr;
        AbstractC4995c[] abstractC4995cArr;
        long j5 = this.j;
        kotlin.coroutines.h[] hVarArr2 = AbstractC4994b.a;
        if (j <= j5) {
            long jQ = q();
            long j6 = this.k + jQ;
            int i2 = this.f;
            if (i2 == 0 && this.l > 0) {
                j6++;
            }
            int i3 = 0;
            if (this.b != 0 && (abstractC4995cArr = this.a) != null) {
                for (AbstractC4995c abstractC4995c : abstractC4995cArr) {
                    if (abstractC4995c != null) {
                        long j7 = ((f0) abstractC4995c).a;
                        if (j7 >= 0 && j7 < j6) {
                            j6 = j7;
                        }
                    }
                }
            }
            if (j6 > this.j) {
                long jQ2 = q() + this.k;
                int iMin = this.b > 0 ? Math.min(this.l, i2 - ((int) (jQ2 - j6))) : this.l;
                long j8 = this.l + jQ2;
                C1472a c1472a = e0.a;
                if (iMin > 0) {
                    kotlin.coroutines.h[] hVarArr3 = new kotlin.coroutines.h[iMin];
                    j4 = 1;
                    Object[] objArr = this.h;
                    Intrinsics.d(objArr);
                    i = i2;
                    long j9 = jQ2;
                    while (true) {
                        if (jQ2 >= j8) {
                            j2 = jQ;
                            j3 = j6;
                            break;
                        }
                        j2 = jQ;
                        Object obj = objArr[((int) jQ2) & (objArr.length - 1)];
                        if (obj != c1472a) {
                            Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.flow.SharedFlowImpl.Emitter");
                            b0 b0Var = (b0) obj;
                            int i4 = i3 + 1;
                            j3 = j6;
                            hVarArr3[i3] = b0Var.d;
                            e0.e(objArr, jQ2, c1472a);
                            e0.e(objArr, j9, b0Var.c);
                            j9++;
                            if (i4 >= iMin) {
                                break;
                            }
                            i3 = i4;
                        } else {
                            j3 = j6;
                        }
                        jQ2++;
                        jQ = j2;
                        j6 = j3;
                    }
                    jQ2 = j9;
                    hVarArr = hVarArr3;
                } else {
                    j2 = jQ;
                    j3 = j6;
                    j4 = 1;
                    i = i2;
                    hVarArr = hVarArr2;
                }
                int i5 = (int) (jQ2 - j2);
                long j10 = this.b == 0 ? jQ2 : j3;
                long jMax = Math.max(this.i, jQ2 - Math.min(this.e, i5));
                if (i == 0 && jMax < j8) {
                    Object[] objArr2 = this.h;
                    Intrinsics.d(objArr2);
                    if (Intrinsics.b(objArr2[((int) jMax) & (objArr2.length - 1)], c1472a)) {
                        jQ2 += j4;
                        jMax += j4;
                    }
                }
                v(jMax, j10, jQ2, j8);
                l();
                return hVarArr.length == 0 ? hVarArr : p(hVarArr);
            }
        }
        return hVarArr2;
    }
}
