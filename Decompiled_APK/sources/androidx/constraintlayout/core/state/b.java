package androidx.constraintlayout.core.state;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.layout.J;
import com.comscore.streaming.ContentDistributionModel;
import java.util.HashMap;

/* loaded from: classes.dex */
public class b implements h {
    public Object a;
    public final androidx.constraintlayout.compose.k b;
    public float b0;
    public float c0;
    public f d0;
    public f e0;
    public J f0;
    public androidx.constraintlayout.core.widgets.e g0;
    public final HashMap h0;
    public HashMap i0;
    public Object c = null;
    public int d = 0;
    public int e = 0;
    public float f = -1.0f;
    public float g = -1.0f;
    public float h = 0.5f;
    public float i = 0.5f;
    public int j = 0;
    public int k = 0;
    public int l = 0;
    public int m = 0;
    public int n = 0;
    public int o = 0;
    public int p = 0;
    public int q = 0;
    public int r = 0;
    public int s = 0;
    public int t = 0;
    public int u = 0;
    public int v = 0;
    public int w = 0;
    public float x = Float.NaN;
    public float y = Float.NaN;
    public float z = Float.NaN;
    public float A = Float.NaN;
    public float B = Float.NaN;
    public float C = Float.NaN;
    public float D = Float.NaN;
    public float E = Float.NaN;
    public float F = Float.NaN;
    public float G = Float.NaN;
    public float H = Float.NaN;
    public int I = 0;
    public Object J = null;
    public Object K = null;
    public Object L = null;
    public Object M = null;
    public Object N = null;
    public Object O = null;
    public Object P = null;
    public Object Q = null;
    public Object R = null;
    public Object S = null;
    public b T = null;
    public Object U = null;
    public Object V = null;
    public b W = null;
    public Object X = null;
    public Object Y = null;
    public Object Z = null;
    public Object a0 = null;
    public int j0 = 0;

    public b(androidx.constraintlayout.compose.k kVar) {
        String str = f.i;
        String str2 = f.h;
        f fVar = new f(str2);
        fVar.f = str;
        this.d0 = fVar;
        f fVar2 = new f(str2);
        fVar2.f = str;
        this.e0 = fVar2;
        this.h0 = new HashMap();
        this.i0 = new HashMap();
        this.b = kVar;
    }

    @Override // androidx.constraintlayout.core.state.h
    public final void a(androidx.constraintlayout.core.widgets.e eVar) {
        if (eVar == null) {
            return;
        }
        this.g0 = eVar;
        eVar.i0 = this.f0;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [androidx.constraintlayout.core.state.helpers.d, java.lang.Object] */
    @Override // androidx.constraintlayout.core.state.h
    public void apply() {
        if (this.g0 == null) {
            return;
        }
        ?? r0 = this.c;
        if (r0 != 0) {
            r0.apply();
        }
        this.d0.a(this.g0, 0);
        this.e0.a(this.g0, 1);
        this.J = j(this.J);
        this.K = j(this.K);
        this.L = j(this.L);
        this.M = j(this.M);
        this.N = j(this.N);
        this.O = j(this.O);
        this.P = j(this.P);
        this.Q = j(this.Q);
        this.R = j(this.R);
        this.S = j(this.S);
        this.U = j(this.U);
        this.V = j(this.V);
        this.X = j(this.X);
        this.Y = j(this.Y);
        this.Z = j(this.Z);
        d(this.g0, this.J, 1);
        d(this.g0, this.K, 2);
        d(this.g0, this.L, 3);
        d(this.g0, this.M, 4);
        d(this.g0, this.N, 5);
        d(this.g0, this.O, 6);
        d(this.g0, this.P, 7);
        d(this.g0, this.Q, 8);
        d(this.g0, this.R, 9);
        d(this.g0, this.S, 10);
        d(this.g0, this.T, 11);
        d(this.g0, this.U, 12);
        d(this.g0, this.V, 13);
        d(this.g0, this.W, 14);
        d(this.g0, this.X, 15);
        d(this.g0, this.Y, 16);
        d(this.g0, this.Z, 17);
        d(this.g0, this.a0, 20);
        int i = this.d;
        if (i != 0) {
            this.g0.m0 = i;
        }
        int i2 = this.e;
        if (i2 != 0) {
            this.g0.n0 = i2;
        }
        float f = this.f;
        if (f != -1.0f) {
            this.g0.o0[0] = f;
        }
        float f2 = this.g;
        if (f2 != -1.0f) {
            this.g0.o0[1] = f2;
        }
        androidx.constraintlayout.core.widgets.e eVar = this.g0;
        eVar.g0 = this.h;
        eVar.h0 = this.i;
        k kVar = eVar.j;
        kVar.d = this.x;
        kVar.e = this.y;
        kVar.f = this.z;
        kVar.g = this.A;
        kVar.h = this.B;
        kVar.i = this.C;
        kVar.j = this.D;
        kVar.k = this.E;
        kVar.l = this.G;
        kVar.m = this.H;
        kVar.n = this.F;
        int i3 = this.I;
        kVar.o = i3;
        eVar.j0 = i3;
        HashMap map = this.h0;
        if (map != null) {
            for (String str : map.keySet()) {
                Integer num = (Integer) map.get(str);
                k kVar2 = this.g0.j;
                int iIntValue = num.intValue();
                HashMap map2 = kVar2.p;
                if (map2.containsKey(str)) {
                    ((androidx.constraintlayout.core.motion.a) map2.get(str)).c = iIntValue;
                } else {
                    androidx.constraintlayout.core.motion.a aVar = new androidx.constraintlayout.core.motion.a();
                    aVar.d = Float.NaN;
                    aVar.a = str;
                    aVar.b = ContentDistributionModel.EXCLUSIVELY_ONLINE;
                    aVar.c = iIntValue;
                    map2.put(str, aVar);
                }
            }
        }
        HashMap map3 = this.i0;
        if (map3 != null) {
            for (String str2 : map3.keySet()) {
                float fFloatValue = ((Float) this.i0.get(str2)).floatValue();
                HashMap map4 = this.g0.j.p;
                if (map4.containsKey(str2)) {
                    ((androidx.constraintlayout.core.motion.a) map4.get(str2)).d = fFloatValue;
                } else {
                    androidx.constraintlayout.core.motion.a aVar2 = new androidx.constraintlayout.core.motion.a();
                    aVar2.c = Integer.MIN_VALUE;
                    aVar2.a = str2;
                    aVar2.b = ContentDistributionModel.TV_AND_ONLINE;
                    aVar2.d = fFloatValue;
                    map4.put(str2, aVar2);
                }
            }
        }
    }

    @Override // androidx.constraintlayout.core.state.h
    public androidx.constraintlayout.core.widgets.e b() {
        if (this.g0 == null) {
            androidx.constraintlayout.core.widgets.e eVar = new androidx.constraintlayout.core.widgets.e(this.d0.d, this.e0.d);
            this.g0 = eVar;
            eVar.i0 = this.f0;
        }
        return this.g0;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [androidx.constraintlayout.core.state.helpers.d, java.lang.Object] */
    @Override // androidx.constraintlayout.core.state.h
    public final androidx.constraintlayout.core.state.helpers.d c() {
        return this.c;
    }

    public final void d(androidx.constraintlayout.core.widgets.e eVar, Object obj, int i) {
        androidx.constraintlayout.core.widgets.e eVarB = obj instanceof h ? ((h) obj).b() : null;
        if (eVarB == null) {
            return;
        }
        int i2 = a.a[AbstractC0147y.k(i)];
        int iK = AbstractC0147y.k(i);
        if (iK == 19) {
            float f = this.b0;
            eVar.w(7, 7, (int) this.c0, 0, eVarB);
            eVar.E = f;
            return;
        }
        switch (iK) {
            case 0:
                eVar.j(2).b(eVarB.j(2), this.j, this.p, false);
                break;
            case 1:
                eVar.j(2).b(eVarB.j(4), this.j, this.p, false);
                break;
            case 2:
                eVar.j(4).b(eVarB.j(2), this.k, this.q, false);
                break;
            case 3:
                eVar.j(4).b(eVarB.j(4), this.k, this.q, false);
                break;
            case 4:
                eVar.j(2).b(eVarB.j(2), this.l, this.r, false);
                break;
            case 5:
                eVar.j(2).b(eVarB.j(4), this.l, this.r, false);
                break;
            case 6:
                eVar.j(4).b(eVarB.j(2), this.m, this.s, false);
                break;
            case 7:
                eVar.j(4).b(eVarB.j(4), this.m, this.s, false);
                break;
            case 8:
                eVar.j(3).b(eVarB.j(3), this.n, this.t, false);
                break;
            case 9:
                eVar.j(3).b(eVarB.j(5), this.n, this.t, false);
                break;
            case 10:
                eVar.w(3, 6, this.n, this.t, eVarB);
                break;
            case 11:
                eVar.j(5).b(eVarB.j(3), this.o, this.u, false);
                break;
            case 12:
                eVar.j(5).b(eVarB.j(5), this.o, this.u, false);
                break;
            case 13:
                eVar.w(5, 6, this.o, this.u, eVarB);
                break;
            case 14:
                eVar.w(6, 6, this.v, this.w, eVarB);
                break;
            case 15:
                eVar.w(6, 3, this.v, this.w, eVarB);
                break;
            case 16:
                eVar.w(6, 5, this.v, this.w, eVarB);
                break;
        }
    }

    public final void e(Object obj) {
        this.j0 = 13;
        this.V = obj;
    }

    public final void f() {
        int i = this.j0;
        if (i == 0) {
            this.J = null;
            this.K = null;
            this.j = 0;
            this.L = null;
            this.M = null;
            this.k = 0;
            this.N = null;
            this.O = null;
            this.l = 0;
            this.P = null;
            this.Q = null;
            this.m = 0;
            this.R = null;
            this.S = null;
            this.n = 0;
            this.U = null;
            this.V = null;
            this.o = 0;
            this.X = null;
            this.a0 = null;
            this.h = 0.5f;
            this.i = 0.5f;
            this.p = 0;
            this.q = 0;
            this.r = 0;
            this.s = 0;
            this.t = 0;
            this.u = 0;
            return;
        }
        int iK = AbstractC0147y.k(i);
        if (iK == 19) {
            this.a0 = null;
            return;
        }
        switch (iK) {
            case 0:
            case 1:
                this.J = null;
                this.K = null;
                this.j = 0;
                this.p = 0;
                break;
            case 2:
            case 3:
                this.L = null;
                this.M = null;
                this.k = 0;
                this.q = 0;
                break;
            case 4:
            case 5:
                this.N = null;
                this.O = null;
                this.l = 0;
                this.r = 0;
                break;
            case 6:
            case 7:
                this.P = null;
                this.Q = null;
                this.m = 0;
                this.s = 0;
                break;
            case 8:
            case 9:
            case 10:
                this.R = null;
                this.S = null;
                this.T = null;
                this.n = 0;
                this.t = 0;
                break;
            case 11:
            case 12:
            case 13:
                this.U = null;
                this.V = null;
                this.W = null;
                this.o = 0;
                this.u = 0;
                break;
            case 14:
                this.X = null;
                break;
        }
    }

    public final void g() {
        if (this.N != null) {
            this.j0 = 5;
        } else {
            this.j0 = 6;
        }
        f();
        if (this.P != null) {
            this.j0 = 7;
        } else {
            this.j0 = 8;
        }
        f();
        if (this.J != null) {
            this.j0 = 1;
        } else {
            this.j0 = 2;
        }
        f();
        if (this.L != null) {
            this.j0 = 3;
        } else {
            this.j0 = 4;
        }
        f();
    }

    @Override // androidx.constraintlayout.core.state.h
    public final Object getKey() {
        return this.a;
    }

    public final void h() {
        if (this.R != null) {
            this.j0 = 9;
        } else {
            this.j0 = 10;
        }
        f();
        this.j0 = 15;
        f();
        if (this.U != null) {
            this.j0 = 12;
        } else {
            this.j0 = 13;
        }
        f();
    }

    public final void i(Object obj) {
        this.j0 = 8;
        this.Q = obj;
    }

    public final Object j(Object obj) {
        if (obj == null) {
            return null;
        }
        return !(obj instanceof b) ? (h) this.b.c.get(obj) : obj;
    }

    public b k(int i) {
        int i2 = this.j0;
        if (i2 == 0) {
            this.j = i;
            this.k = i;
            this.l = i;
            this.m = i;
            this.n = i;
            this.o = i;
            return this;
        }
        int iK = AbstractC0147y.k(i2);
        if (iK == 19) {
            this.c0 = i;
            return this;
        }
        switch (iK) {
            case 0:
            case 1:
                this.j = i;
                break;
            case 2:
            case 3:
                this.k = i;
                break;
            case 4:
            case 5:
                this.l = i;
                break;
            case 6:
            case 7:
                this.m = i;
                break;
            case 8:
            case 9:
            case 10:
                this.n = i;
                break;
            case 11:
            case 12:
            case 13:
                this.o = i;
                break;
            case 14:
            case 15:
            case 16:
                this.v = i;
                break;
        }
        return this;
    }

    public b l(Float f) {
        return k(this.b.c(f));
    }

    public final void m(int i) {
        int i2 = this.j0;
        if (i2 == 0) {
            this.p = i;
            this.q = i;
            this.r = i;
            this.s = i;
            this.t = i;
            this.u = i;
            return;
        }
        switch (AbstractC0147y.k(i2)) {
            case 0:
            case 1:
                this.p = i;
                break;
            case 2:
            case 3:
                this.q = i;
                break;
            case 4:
            case 5:
                this.r = i;
                break;
            case 6:
            case 7:
                this.s = i;
                break;
            case 8:
            case 9:
            case 10:
                this.t = i;
                break;
            case 11:
            case 12:
            case 13:
                this.u = i;
                break;
            case 14:
            case 15:
            case 16:
                this.w = i;
                break;
        }
    }

    public final void n(Float f) {
        m(this.b.c(f));
    }

    public final void o(Object obj) {
        this.j0 = 5;
        this.N = obj;
    }

    public final void p(Object obj) {
        this.j0 = 9;
        this.R = obj;
    }
}
