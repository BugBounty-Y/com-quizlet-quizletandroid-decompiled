package androidx.compose.runtime;

import androidx.collection.C0222u;
import androidx.collection.C0223v;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D0 {
    public final A0 a;
    public int[] b;
    public Object[] c;
    public ArrayList d;
    public HashMap e;
    public C0223v f;
    public int g;
    public int h;
    public int i;
    public int j;
    public int k;
    public int l;
    public int m;
    public int n;
    public int o;
    public final N p;
    public final N q;
    public final N r;
    public C0223v s;
    public int t;
    public int u;
    public int v;
    public boolean w;
    public C0222u x;

    public D0(A0 a0) {
        this.a = a0;
        int[] iArr = a0.a;
        this.b = iArr;
        Object[] objArr = a0.c;
        this.c = objArr;
        this.d = a0.i;
        this.e = a0.j;
        this.f = a0.k;
        int i = a0.b;
        this.g = i;
        this.h = (iArr.length / 5) - i;
        int i2 = a0.d;
        this.k = i2;
        this.l = objArr.length - i2;
        this.m = i;
        this.p = new N();
        this.q = new N();
        this.r = new N();
        this.u = i;
        this.v = -1;
    }

    public static int h(int i, int i2, int i3, int i4) {
        return i > i2 ? -(((i4 - i3) - i) + 1) : i;
    }

    public static void x(D0 d0) {
        int i = d0.v;
        int iQ = d0.q(i);
        int[] iArr = d0.b;
        int i2 = (iQ * 5) + 1;
        int i3 = iArr[i2];
        if ((i3 & 134217728) != 0) {
            return;
        }
        int i4 = (i3 & (-134217729)) | 134217728;
        iArr[i2] = i4;
        if ((67108864 & i4) != 0) {
            return;
        }
        d0.U(d0.E(iArr, i));
    }

    public final void A(int i, int i2) {
        int i3 = this.l;
        int i4 = this.k;
        int i5 = this.m;
        if (i4 != i) {
            Object[] objArr = this.c;
            if (i < i4) {
                System.arraycopy(objArr, i, objArr, i + i3, i4 - i);
            } else {
                int i6 = i4 + i3;
                System.arraycopy(objArr, i6, objArr, i4, (i + i3) - i6);
            }
        }
        int iMin = Math.min(i2 + 1, n());
        if (i5 != iMin) {
            int length = this.c.length - i3;
            if (iMin < i5) {
                int iQ = q(iMin);
                int iQ2 = q(i5);
                int i7 = this.g;
                while (iQ < iQ2) {
                    int i8 = (iQ * 5) + 4;
                    int i9 = this.b[i8];
                    if (!(i9 >= 0)) {
                        r.c("Unexpected anchor value, expected a positive anchor");
                    }
                    this.b[i8] = -((length - i9) + 1);
                    iQ++;
                    if (iQ == i7) {
                        iQ += this.h;
                    }
                }
            } else {
                int iQ3 = q(i5);
                int iQ4 = q(iMin);
                while (iQ3 < iQ4) {
                    int i10 = (iQ3 * 5) + 4;
                    int i11 = this.b[i10];
                    if (!(i11 < 0)) {
                        r.c("Unexpected anchor value, expected a negative anchor");
                    }
                    this.b[i10] = i11 + length + 1;
                    iQ3++;
                    if (iQ3 == this.g) {
                        iQ3 += this.h;
                    }
                }
            }
            this.m = iMin;
        }
        this.k = i;
    }

    public final List B(C0774b c0774b, D0 d0) {
        if (!(d0.n > 0)) {
            r.c("Check failed");
        }
        if (this.n != 0) {
            r.c("Check failed");
        }
        if (!c0774b.a()) {
            r.c("Check failed");
        }
        int iC = c(c0774b) + 1;
        int i = this.t;
        if (i > iC || iC >= this.u) {
            r.c("Check failed");
        }
        int iE = E(this.b, iC);
        int iS = s(iC);
        int iD = w(iC) ? 1 : D(iC);
        List listU = C0776c.u(this, iC, d0, false, false, true);
        U(iE);
        boolean z = iD > 0;
        while (iE >= i) {
            int iQ = q(iE);
            int[] iArr = this.b;
            int i2 = iQ * 5;
            int i3 = i2 + 3;
            iArr[i3] = iArr[i3] - iS;
            if (z) {
                int i4 = iArr[i2 + 1];
                if ((1073741824 & i4) != 0) {
                    z = false;
                } else {
                    C0.d(iQ, (i4 & 67108863) - iD, iArr);
                }
            }
            iE = E(this.b, iE);
        }
        if (z) {
            if (this.o < iD) {
                r.c("Check failed");
            }
            this.o -= iD;
        }
        return listU;
    }

    public final Object C(int i) {
        int iQ = q(i);
        int[] iArr = this.b;
        if ((iArr[(iQ * 5) + 1] & 1073741824) != 0) {
            return this.c[g(f(iArr, iQ))];
        }
        return null;
    }

    public final int D(int i) {
        return this.b[(q(i) * 5) + 1] & 67108863;
    }

    public final int E(int[] iArr, int i) {
        int i2 = iArr[(q(i) * 5) + 2];
        return i2 > -2 ? i2 : (n() + i2) - (-2);
    }

    public final Object F(Object obj) {
        if (this.n > 0) {
            v(1, this.v);
        }
        Object[] objArr = this.c;
        int i = this.i;
        this.i = i + 1;
        Object obj2 = objArr[g(i)];
        if (this.i > this.j) {
            r.c("Writing to an invalid slot");
        }
        this.c[g(this.i - 1)] = obj;
        return obj2;
    }

    public final void G() {
        int i;
        C0222u c0222u = this.x;
        if (c0222u != null) {
            while (c0222u.b != 0) {
                int iG = C0776c.G(c0222u);
                int iQ = q(iG);
                int iS = iG + 1;
                int iS2 = s(iG) + iG;
                while (true) {
                    if (iS >= iS2) {
                        i = 0;
                        break;
                    } else {
                        if ((this.b[(q(iS) * 5) + 1] & 201326592) != 0) {
                            i = 1;
                            break;
                        }
                        iS += s(iS);
                    }
                }
                int[] iArr = this.b;
                int i2 = (iQ * 5) + 1;
                int i3 = iArr[i2];
                if (((67108864 & i3) == 0 ? 0 : 1) != i) {
                    iArr[i2] = (i << 26) | ((-67108865) & i3);
                    int iE = E(iArr, iG);
                    if (iE >= 0) {
                        C0776c.j(c0222u, iE);
                    }
                }
            }
        }
    }

    public final boolean H() {
        C0774b c0774bR;
        if (this.n != 0) {
            r.c("Cannot remove group while inserting");
        }
        int i = this.t;
        int i2 = this.i;
        int iF = f(this.b, q(i));
        int iK = K();
        int i3 = this.v;
        HashMap map = this.e;
        if (map != null && (c0774bR = R(i3)) != null) {
        }
        C0222u c0222u = this.x;
        if (c0222u != null) {
            while (true) {
                int i4 = c0222u.b;
                if (i4 == 0) {
                    break;
                }
                if (i4 == 0) {
                    androidx.collection.internal.a.e("IntList is empty.");
                    throw null;
                }
                if (c0222u.a[0] < i) {
                    break;
                }
                C0776c.G(c0222u);
            }
        }
        boolean zI = I(i, this.t - i);
        J(iF, this.i - iF, i - 1);
        this.t = i;
        this.i = i2;
        this.o -= iK;
        return zI;
    }

    public final boolean I(int i, int i2) {
        if (i2 > 0) {
            ArrayList arrayList = this.d;
            z(i);
            if (!arrayList.isEmpty()) {
                HashMap map = this.e;
                int i3 = i + i2;
                int iB = C0.b(this.d, i3, m() - this.h);
                if (iB >= this.d.size()) {
                    iB--;
                }
                int i4 = iB + 1;
                int i5 = 0;
                while (iB >= 0) {
                    C0774b c0774b = (C0774b) this.d.get(iB);
                    int iC = c(c0774b);
                    if (iC < i) {
                        break;
                    }
                    if (iC < i3) {
                        c0774b.a = Integer.MIN_VALUE;
                        if (map != null) {
                        }
                        if (i5 == 0) {
                            i5 = iB + 1;
                        }
                        i4 = iB;
                    }
                    iB--;
                }
                z = i4 < i5;
                if (z) {
                    this.d.subList(i4, i5).clear();
                }
            }
            this.g = i;
            this.h += i2;
            int i6 = this.m;
            if (i6 > i) {
                this.m = Math.max(i, i6 - i2);
            }
            int i7 = this.u;
            if (i7 >= this.g) {
                this.u = i7 - i2;
            }
            int i8 = this.v;
            if (i8 >= 0 && (this.b[(q(i8) * 5) + 1] & 67108864) != 0) {
                U(i8);
            }
        }
        return z;
    }

    public final void J(int i, int i2, int i3) {
        if (i2 > 0) {
            int i4 = this.l;
            int i5 = i + i2;
            A(i5, i3);
            this.k = i;
            this.l = i4 + i2;
            Object[] objArr = this.c;
            Intrinsics.checkNotNullParameter(objArr, "<this>");
            Arrays.fill(objArr, i, i5, (Object) null);
            int i6 = this.j;
            if (i6 >= i) {
                this.j = i6 - i2;
            }
        }
    }

    public final int K() {
        int iQ = q(this.t);
        int iA = C0.a(this.b, iQ) + this.t;
        this.t = iA;
        this.i = f(this.b, q(iA));
        int i = this.b[(iQ * 5) + 1];
        if ((1073741824 & i) != 0) {
            return 1;
        }
        return i & 67108863;
    }

    public final void L() {
        int i = this.u;
        this.t = i;
        this.i = f(this.b, q(i));
    }

    public final int M(int[] iArr, int i) {
        if (i >= m()) {
            return this.c.length - this.l;
        }
        int iC = C0.c(iArr, i);
        return iC < 0 ? (this.c.length - this.l) + iC + 1 : iC;
    }

    public final int N(int i, int i2) {
        int iM = M(this.b, q(i));
        int i3 = iM + i2;
        if (!(i3 >= iM && i3 < f(this.b, q(i + 1)))) {
            r.c("Write to an invalid slot index " + i2 + " for group " + i);
        }
        return i3;
    }

    public final int O(int i) {
        return f(this.b, q(s(i) + i));
    }

    public final void P() {
        if (this.n != 0) {
            r.c("Key must be supplied when inserting");
        }
        V v = C0804k.a;
        Q(v, false, v, 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void Q(Object obj, boolean z, Object obj2, int i) {
        int i2;
        HashMap map;
        C0774b c0774bR;
        int i3 = this.v;
        Object[] objArr = this.n > 0;
        this.r.c(this.o);
        V v = C0804k.a;
        if (objArr == true) {
            int i4 = this.t;
            int iF = f(this.b, q(i4));
            u(1);
            this.i = iF;
            this.j = iF;
            int iQ = q(i4);
            int i5 = obj != v ? 1 : 0;
            int i6 = (z || obj2 == v) ? 0 : 1;
            int iH = h(iF, this.k, this.l, this.c.length);
            if (iH >= 0 && this.m < i4) {
                iH = -(((this.c.length - this.l) - iH) + 1);
            }
            int[] iArr = this.b;
            int i7 = this.v;
            int i8 = iQ * 5;
            iArr[i8] = i;
            iArr[i8 + 1] = ((z ? 1 : 0) << 30) | (i5 << 29) | (i6 << 28);
            iArr[i8 + 2] = i7;
            iArr[i8 + 3] = 0;
            iArr[i8 + 4] = iH;
            int i9 = (z ? 1 : 0) + i5 + i6;
            if (i9 > 0) {
                v(i9, i4);
                Object[] objArr2 = this.c;
                int i10 = this.i;
                if (z) {
                    objArr2[i10] = obj2;
                    i10++;
                }
                if (i5 != 0) {
                    objArr2[i10] = obj;
                    i10++;
                }
                if (i6 != 0) {
                    objArr2[i10] = obj2;
                    i10++;
                }
                this.i = i10;
            }
            this.o = 0;
            i2 = i4 + 1;
            this.v = i4;
            this.t = i2;
            if (i3 >= 0 && (map = this.e) != null && (c0774bR = R(i3)) != null) {
            }
        } else {
            this.p.c(i3);
            this.q.c((m() - this.h) - this.u);
            int i11 = this.t;
            int iQ2 = q(i11);
            if (!Intrinsics.b(obj2, v)) {
                if (z) {
                    V(this.t, obj2);
                } else {
                    T(obj2);
                }
            }
            this.i = M(this.b, iQ2);
            this.j = f(this.b, q(this.t + 1));
            int[] iArr2 = this.b;
            int i12 = iQ2 * 5;
            this.o = iArr2[i12 + 1] & 67108863;
            this.v = i11;
            this.t = i11 + 1;
            i2 = i11 + iArr2[i12 + 3];
        }
        this.u = i2;
    }

    public final C0774b R(int i) {
        ArrayList arrayList;
        int iE;
        if (i < 0 || i >= n() || (iE = C0.e((arrayList = this.d), i, n())) < 0) {
            return null;
        }
        return (C0774b) arrayList.get(iE);
    }

    public final void S(Object obj) {
        if (this.n <= 0 || this.i == this.k) {
            F(obj);
            return;
        }
        C0223v c0223v = this.s;
        if (c0223v == null) {
            c0223v = new C0223v();
        }
        this.s = c0223v;
        int i = this.v;
        Object objE = c0223v.e(i);
        if (objE == null) {
            objE = new androidx.collection.G();
            c0223v.h(i, objE);
        }
        ((androidx.collection.G) objE).a(obj);
    }

    public final void T(Object obj) {
        int iQ = q(this.t);
        int i = (iQ * 5) + 1;
        if ((this.b[i] & 268435456) == 0) {
            r.c("Updating the data of a group that was not created with a data slot");
        }
        Object[] objArr = this.c;
        int[] iArr = this.b;
        objArr[g(Integer.bitCount(iArr[i] >> 29) + f(iArr, iQ))] = obj;
    }

    public final void U(int i) {
        if (i >= 0) {
            C0222u c0222u = this.x;
            if (c0222u == null) {
                c0222u = new C0222u();
                this.x = c0222u;
            }
            C0776c.j(c0222u, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void V(int r5, java.lang.Object r6) {
        /*
            r4 = this;
            int r0 = r4.q(r5)
            int[] r1 = r4.b
            int r2 = r1.length
            if (r0 >= r2) goto L15
            int r2 = r0 * 5
            r3 = 1
            int r2 = r2 + r3
            r1 = r1[r2]
            r2 = 1073741824(0x40000000, float:2.0)
            r1 = r1 & r2
            if (r1 == 0) goto L15
            goto L16
        L15:
            r3 = 0
        L16:
            if (r3 != 0) goto L2e
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Updating the node of a group at "
            r1.<init>(r2)
            r1.append(r5)
            java.lang.String r5 = " that was not created with as a node group"
            r1.append(r5)
            java.lang.String r5 = r1.toString()
            androidx.compose.runtime.r.c(r5)
        L2e:
            java.lang.Object[] r5 = r4.c
            int[] r1 = r4.b
            int r0 = r4.f(r1, r0)
            int r0 = r4.g(r0)
            r5[r0] = r6
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.D0.V(int, java.lang.Object):void");
    }

    public final void a(int i) {
        boolean z = false;
        if (!(i >= 0)) {
            r.c("Cannot seek backwards");
        }
        if (!(this.n <= 0)) {
            AbstractC0805k0.b("Cannot call seek() while inserting");
        }
        if (i == 0) {
            return;
        }
        int i2 = this.t + i;
        if (i2 >= this.v && i2 <= this.u) {
            z = true;
        }
        if (!z) {
            r.c("Cannot seek outside the current group (" + this.v + '-' + this.u + ')');
        }
        this.t = i2;
        int iF = f(this.b, q(i2));
        this.i = iF;
        this.j = iF;
    }

    public final C0774b b(int i) {
        ArrayList arrayList = this.d;
        int iE = C0.e(arrayList, i, n());
        if (iE >= 0) {
            return (C0774b) arrayList.get(iE);
        }
        if (i > this.g) {
            i = -(n() - i);
        }
        C0774b c0774b = new C0774b(i);
        arrayList.add(-(iE + 1), c0774b);
        return c0774b;
    }

    public final int c(C0774b c0774b) {
        int i = c0774b.a;
        return i < 0 ? n() + i : i;
    }

    public final void d() {
        int i = this.n;
        this.n = i + 1;
        if (i == 0) {
            this.q.c((m() - this.h) - this.u);
        }
    }

    public final void e(boolean z) {
        this.w = true;
        if (z && this.p.b == 0) {
            z(n());
            A(this.c.length - this.l, this.g);
            int i = this.k;
            int i2 = this.l + i;
            Object[] objArr = this.c;
            Intrinsics.checkNotNullParameter(objArr, "<this>");
            Arrays.fill(objArr, i, i2, (Object) null);
            G();
        }
        int[] iArr = this.b;
        int i3 = this.g;
        Object[] objArr2 = this.c;
        int i4 = this.k;
        ArrayList arrayList = this.d;
        HashMap map = this.e;
        C0223v c0223v = this.f;
        A0 a0 = this.a;
        a0.getClass();
        if (!a0.g) {
            AbstractC0805k0.a("Unexpected writer close()");
        }
        a0.g = false;
        a0.a = iArr;
        a0.b = i3;
        a0.c = objArr2;
        a0.d = i4;
        a0.i = arrayList;
        a0.j = map;
        a0.k = c0223v;
    }

    public final int f(int[] iArr, int i) {
        if (i >= m()) {
            return this.c.length - this.l;
        }
        int i2 = iArr[(i * 5) + 4];
        return i2 < 0 ? (this.c.length - this.l) + i2 + 1 : i2;
    }

    public final int g(int i) {
        return (this.l * (i < this.k ? 0 : 1)) + i;
    }

    public final void i() {
        androidx.collection.G g;
        boolean z = this.n > 0;
        int i = this.t;
        int i2 = this.u;
        int i3 = this.v;
        int iQ = q(i3);
        int i4 = this.o;
        int i5 = i - i3;
        int i6 = iQ * 5;
        int i7 = i6 + 1;
        boolean z2 = (this.b[i7] & 1073741824) != 0;
        N n = this.r;
        if (z) {
            C0223v c0223v = this.s;
            if (c0223v != null && (g = (androidx.collection.G) c0223v.e(i3)) != null) {
                Object[] objArr = g.a;
                int i8 = g.b;
                for (int i9 = 0; i9 < i8; i9++) {
                    F(objArr[i9]);
                }
            }
            int[] iArr = this.b;
            iArr[i6 + 3] = i5;
            C0.d(iQ, i4, iArr);
            int iB = n.b();
            if (z2) {
                i4 = 1;
            }
            this.o = iB + i4;
            int iE = E(this.b, i3);
            this.v = iE;
            int iN = iE < 0 ? n() : q(iE + 1);
            int iF = iN >= 0 ? f(this.b, iN) : 0;
            this.i = iF;
            this.j = iF;
            return;
        }
        if (i != i2) {
            r.c("Expected to be at the end of a group");
        }
        int[] iArr2 = this.b;
        int i10 = i6 + 3;
        int i11 = iArr2[i10];
        int i12 = iArr2[i7] & 67108863;
        iArr2[i10] = i5;
        C0.d(iQ, i4, iArr2);
        int iB2 = this.p.b();
        this.u = (m() - this.h) - this.q.b();
        this.v = iB2;
        int iE2 = E(this.b, i3);
        int iB3 = n.b();
        this.o = iB3;
        if (iE2 == iB2) {
            this.o = iB3 + (z2 ? 0 : i4 - i12);
            return;
        }
        int i13 = i5 - i11;
        int i14 = z2 ? 0 : i4 - i12;
        if (i13 != 0 || i14 != 0) {
            while (iE2 != 0 && iE2 != iB2 && (i14 != 0 || i13 != 0)) {
                int iQ2 = q(iE2);
                if (i13 != 0) {
                    int[] iArr3 = this.b;
                    int i15 = (iQ2 * 5) + 3;
                    iArr3[i15] = iArr3[i15] + i13;
                }
                if (i14 != 0) {
                    int[] iArr4 = this.b;
                    C0.d(iQ2, (iArr4[(iQ2 * 5) + 1] & 67108863) + i14, iArr4);
                }
                int[] iArr5 = this.b;
                if ((iArr5[(iQ2 * 5) + 1] & 1073741824) != 0) {
                    i14 = 0;
                }
                iE2 = E(iArr5, iE2);
            }
        }
        this.o += i14;
    }

    public final void j() {
        if (this.n <= 0) {
            AbstractC0805k0.b("Unbalanced begin/end insert");
        }
        int i = this.n - 1;
        this.n = i;
        if (i == 0) {
            if (this.r.b != this.p.b) {
                r.c("startGroup/endGroup mismatch while inserting");
            }
            this.u = (m() - this.h) - this.q.b();
        }
    }

    public final void k(int i) {
        boolean z = false;
        if (!(this.n <= 0)) {
            r.c("Cannot call ensureStarted() while inserting");
        }
        int i2 = this.v;
        if (i2 != i) {
            if (i >= i2 && i < this.u) {
                z = true;
            }
            if (!z) {
                r.c("Started group at " + i + " must be a subgroup of the group at " + i2);
            }
            int i3 = this.t;
            int i4 = this.i;
            int i5 = this.j;
            this.t = i;
            P();
            this.t = i3;
            this.i = i4;
            this.j = i5;
        }
    }

    public final void l(int i, int i2, int i3) {
        if (i >= this.g) {
            i = -((n() - i) + 2);
        }
        while (i3 < i2) {
            this.b[(q(i3) * 5) + 2] = i;
            int i4 = this.b[(q(i3) * 5) + 3] + i3;
            l(i3, i4, i3 + 1);
            i3 = i4;
        }
    }

    public final int m() {
        return this.b.length / 5;
    }

    public final int n() {
        return m() - this.h;
    }

    public final int o() {
        return this.c.length - this.l;
    }

    public final Object p(int i) {
        int iQ = q(i);
        int[] iArr = this.b;
        int i2 = (iQ * 5) + 1;
        if ((iArr[i2] & 268435456) == 0) {
            return C0804k.a;
        }
        return this.c[Integer.bitCount(iArr[i2] >> 29) + f(iArr, iQ)];
    }

    public final int q(int i) {
        return (this.h * (i < this.g ? 0 : 1)) + i;
    }

    public final Object r(int i) {
        int iQ = q(i);
        int[] iArr = this.b;
        int i2 = iQ * 5;
        int i3 = iArr[i2 + 1];
        if ((536870912 & i3) == 0) {
            return null;
        }
        return this.c[Integer.bitCount(i3 >> 30) + iArr[i2 + 4]];
    }

    public final int s(int i) {
        return C0.a(this.b, q(i));
    }

    public final boolean t(int i, int i2) {
        int iM;
        int iS;
        if (i2 == this.v) {
            iM = this.u;
        } else {
            N n = this.p;
            if (i2 > n.a(0)) {
                iS = s(i2);
            } else {
                int[] iArr = n.a;
                int iMin = Math.min(iArr.length, n.b);
                int i3 = 0;
                while (true) {
                    if (i3 >= iMin) {
                        i3 = -1;
                        break;
                    }
                    if (iArr[i3] == i2) {
                        break;
                    }
                    i3++;
                }
                if (i3 < 0) {
                    iS = s(i2);
                } else {
                    iM = (m() - this.h) - this.q.a[i3];
                }
            }
            iM = iS + i2;
        }
        return i > i2 && i < iM;
    }

    public final String toString() {
        return "SlotWriter(current = " + this.t + " end=" + this.u + " size = " + n() + " gap=" + this.g + '-' + (this.g + this.h) + ')';
    }

    public final void u(int i) {
        if (i > 0) {
            int i2 = this.t;
            z(i2);
            int i3 = this.g;
            int i4 = this.h;
            int[] iArr = this.b;
            int length = iArr.length / 5;
            int i5 = length - i4;
            if (i4 < i) {
                int iMax = Math.max(Math.max(length * 2, i5 + i), 32);
                int[] iArr2 = new int[iMax * 5];
                int i6 = iMax - i5;
                C4930v.e(0, 0, i3 * 5, iArr, iArr2);
                C4930v.e((i3 + i6) * 5, (i4 + i3) * 5, length * 5, iArr, iArr2);
                this.b = iArr2;
                i4 = i6;
            }
            int i7 = this.u;
            if (i7 >= i3) {
                this.u = i7 + i;
            }
            int i8 = i3 + i;
            this.g = i8;
            this.h = i4 - i;
            int iH = h(i5 > 0 ? f(this.b, q(i2 + i)) : 0, this.m >= i3 ? this.k : 0, this.l, this.c.length);
            for (int i9 = i3; i9 < i8; i9++) {
                this.b[(i9 * 5) + 4] = iH;
            }
            int i10 = this.m;
            if (i10 >= i3) {
                this.m = i10 + i;
            }
        }
    }

    public final void v(int i, int i2) {
        if (i > 0) {
            A(this.i, i2);
            int i3 = this.k;
            int i4 = this.l;
            if (i4 < i) {
                Object[] objArr = this.c;
                int length = objArr.length;
                int i5 = length - i4;
                int iMax = Math.max(Math.max(length * 2, i5 + i), 32);
                Object[] objArr2 = new Object[iMax];
                for (int i6 = 0; i6 < iMax; i6++) {
                    objArr2[i6] = null;
                }
                int i7 = iMax - i5;
                int i8 = i4 + i3;
                System.arraycopy(objArr, 0, objArr2, 0, i3);
                System.arraycopy(objArr, i8, objArr2, i3 + i7, length - i8);
                this.c = objArr2;
                i4 = i7;
            }
            int i9 = this.j;
            if (i9 >= i3) {
                this.j = i9 + i;
            }
            this.k = i3 + i;
            this.l = i4 - i;
        }
    }

    public final boolean w(int i) {
        return (this.b[(q(i) * 5) + 1] & 1073741824) != 0;
    }

    public final void y(A0 a0, int i) {
        if (this.n <= 0) {
            r.c("Check failed");
        }
        if (i == 0 && this.t == 0 && this.a.b == 0) {
            int[] iArr = a0.a;
            int i2 = iArr[(i * 5) + 3];
            int i3 = a0.b;
            if (i2 == i3) {
                int[] iArr2 = this.b;
                Object[] objArr = this.c;
                ArrayList arrayList = this.d;
                HashMap map = this.e;
                C0223v c0223v = this.f;
                Object[] objArr2 = a0.c;
                int i4 = a0.d;
                HashMap map2 = a0.j;
                C0223v c0223v2 = a0.k;
                this.b = iArr;
                this.c = objArr2;
                this.d = a0.i;
                this.g = i3;
                this.h = (iArr.length / 5) - i3;
                this.k = i4;
                this.l = objArr2.length - i4;
                this.m = i3;
                this.e = map2;
                this.f = c0223v2;
                a0.a = iArr2;
                a0.b = 0;
                a0.c = objArr;
                a0.d = 0;
                a0.i = arrayList;
                a0.j = map;
                a0.k = c0223v;
                return;
            }
        }
        D0 d0G = a0.g();
        try {
            C0776c.u(d0G, i, this, true, true, false);
            d0G.e(true);
        } catch (Throwable th) {
            d0G.e(false);
            throw th;
        }
    }

    public final void z(int i) {
        C0774b c0774b;
        int i2;
        C0774b c0774b2;
        int i3;
        int i4;
        int i5 = this.h;
        int i6 = this.g;
        if (i6 != i) {
            if (!this.d.isEmpty()) {
                int iM = m() - this.h;
                if (i6 < i) {
                    for (int iB = C0.b(this.d, i6, iM); iB < this.d.size() && (i3 = (c0774b2 = (C0774b) this.d.get(iB)).a) < 0 && (i4 = i3 + iM) < i; iB++) {
                        c0774b2.a = i4;
                    }
                } else {
                    for (int iB2 = C0.b(this.d, i, iM); iB2 < this.d.size() && (i2 = (c0774b = (C0774b) this.d.get(iB2)).a) >= 0; iB2++) {
                        c0774b.a = -(iM - i2);
                    }
                }
            }
            if (i5 > 0) {
                int[] iArr = this.b;
                int i7 = i * 5;
                int i8 = i5 * 5;
                int i9 = i6 * 5;
                if (i < i6) {
                    C4930v.e(i8 + i7, i7, i9, iArr, iArr);
                } else {
                    C4930v.e(i9, i9 + i8, i7 + i8, iArr, iArr);
                }
            }
            if (i < i6) {
                i6 = i + i5;
            }
            int iM2 = m();
            if (i6 >= iM2) {
                r.c("Check failed");
            }
            while (i6 < iM2) {
                int i10 = (i6 * 5) + 2;
                int i11 = this.b[i10];
                int iN = i11 > -2 ? i11 : (n() + i11) - (-2);
                if (iN >= i) {
                    iN = -((n() - iN) - (-2));
                }
                if (iN != i11) {
                    this.b[i10] = iN;
                }
                i6++;
                if (i6 == i) {
                    i6 += i5;
                }
            }
        }
        this.g = i;
    }
}
