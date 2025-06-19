package androidx.constraintlayout.core.widgets;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.core.widgets.analyzer.n;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public class e {
    public float A;
    public int B;
    public float C;
    public final int[] D;
    public float E;
    public boolean F;
    public boolean G;
    public boolean H;
    public int I;
    public int J;
    public final c K;
    public final c L;
    public final c M;
    public final c N;
    public final c O;
    public final c P;
    public final c Q;
    public final c R;
    public final c[] S;
    public final ArrayList T;
    public final boolean[] U;
    public final d[] V;
    public e W;
    public int X;
    public int Y;
    public float Z;
    public boolean a;
    public int a0;
    public androidx.constraintlayout.core.widgets.analyzer.d b;
    public int b0;
    public androidx.constraintlayout.core.widgets.analyzer.d c;
    public int c0;
    public androidx.constraintlayout.core.widgets.analyzer.l d;
    public int d0;
    public n e;
    public int e0;
    public final boolean[] f;
    public int f0;
    public boolean g;
    public float g0;
    public int h;
    public float h0;
    public int i;
    public Object i0;
    public final androidx.constraintlayout.core.state.k j;
    public int j0;
    public String k;
    public final boolean k0;
    public boolean l;
    public String l0;
    public boolean m;
    public int m0;
    public boolean n;
    public int n0;
    public boolean o;
    public final float[] o0;
    public int p;
    public final e[] p0;
    public int q;
    public final e[] q0;
    public int r;
    public int r0;
    public int s;
    public int s0;
    public int t;
    public final int[] u;
    public int v;
    public int w;
    public float x;
    public int y;
    public int z;

    public e() {
        this.a = false;
        this.d = null;
        this.e = null;
        this.f = new boolean[]{true, true};
        this.g = true;
        this.h = -1;
        this.i = -1;
        this.j = new androidx.constraintlayout.core.state.k(this);
        this.l = false;
        this.m = false;
        this.n = false;
        this.o = false;
        this.p = -1;
        this.q = -1;
        this.r = 0;
        this.s = 0;
        this.t = 0;
        this.u = new int[2];
        this.v = 0;
        this.w = 0;
        this.x = 1.0f;
        this.y = 0;
        this.z = 0;
        this.A = 1.0f;
        this.B = -1;
        this.C = 1.0f;
        this.D = new int[]{SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO};
        this.E = Float.NaN;
        this.F = false;
        this.H = false;
        this.I = 0;
        this.J = 0;
        c cVar = new c(this, 2);
        this.K = cVar;
        c cVar2 = new c(this, 3);
        this.L = cVar2;
        c cVar3 = new c(this, 4);
        this.M = cVar3;
        c cVar4 = new c(this, 5);
        this.N = cVar4;
        c cVar5 = new c(this, 6);
        this.O = cVar5;
        this.P = new c(this, 8);
        this.Q = new c(this, 9);
        c cVar6 = new c(this, 7);
        this.R = cVar6;
        this.S = new c[]{cVar, cVar3, cVar2, cVar4, cVar5, cVar6};
        this.T = new ArrayList();
        this.U = new boolean[2];
        d dVar = d.a;
        this.V = new d[]{dVar, dVar};
        this.W = null;
        this.X = 0;
        this.Y = 0;
        this.Z = DefinitionKt.NO_Float_VALUE;
        this.a0 = -1;
        this.b0 = 0;
        this.c0 = 0;
        this.d0 = 0;
        this.g0 = 0.5f;
        this.h0 = 0.5f;
        this.j0 = 0;
        this.k0 = false;
        this.l0 = null;
        this.m0 = 0;
        this.n0 = 0;
        this.o0 = new float[]{-1.0f, -1.0f};
        this.p0 = new e[]{null, null};
        this.q0 = new e[]{null, null};
        this.r0 = -1;
        this.s0 = -1;
        a();
    }

    public static void H(int i, int i2, String str, StringBuilder sb) {
        if (i == i2) {
            return;
        }
        sb.append(str);
        sb.append(" :   ");
        sb.append(i);
        sb.append(",\n");
    }

    public static void I(StringBuilder sb, String str, float f, float f2) {
        if (f == f2) {
            return;
        }
        sb.append(str);
        sb.append(" :   ");
        sb.append(f);
        sb.append(",\n");
    }

    public static void p(StringBuilder sb, String str, int i, int i2, int i3, int i4, int i5, float f, d dVar) {
        sb.append(str);
        sb.append(" :  {\n");
        String string = dVar.toString();
        if (!"FIXED".equals(string)) {
            B.u(sb, "      behavior", " :   ", string, ",\n");
        }
        H(i, 0, "      size", sb);
        H(i2, 0, "      min", sb);
        H(i3, SubsamplingScaleImageView.TILE_SIZE_AUTO, "      max", sb);
        H(i4, 0, "      matchMin", sb);
        H(i5, 0, "      matchDef", sb);
        I(sb, "      matchPercent", f, 1.0f);
        sb.append("    },\n");
    }

    public static void q(StringBuilder sb, String str, c cVar) {
        if (cVar.f == null) {
            return;
        }
        sb.append("    ");
        sb.append(str);
        sb.append(" : [ '");
        sb.append(cVar.f);
        sb.append("'");
        if (cVar.h != Integer.MIN_VALUE || cVar.g != 0) {
            sb.append(",");
            sb.append(cVar.g);
            if (cVar.h != Integer.MIN_VALUE) {
                sb.append(",");
                sb.append(cVar.h);
                sb.append(",");
            }
        }
        sb.append(" ] ,\n");
    }

    public final boolean A() {
        return this.g && this.j0 != 8;
    }

    public boolean B() {
        if (this.l) {
            return true;
        }
        return this.K.c && this.M.c;
    }

    public boolean C() {
        if (this.m) {
            return true;
        }
        return this.L.c && this.N.c;
    }

    public void D() {
        this.K.j();
        this.L.j();
        this.M.j();
        this.N.j();
        this.O.j();
        this.P.j();
        this.Q.j();
        this.R.j();
        this.W = null;
        this.E = Float.NaN;
        this.X = 0;
        this.Y = 0;
        this.Z = DefinitionKt.NO_Float_VALUE;
        this.a0 = -1;
        this.b0 = 0;
        this.c0 = 0;
        this.d0 = 0;
        this.e0 = 0;
        this.f0 = 0;
        this.g0 = 0.5f;
        this.h0 = 0.5f;
        d[] dVarArr = this.V;
        d dVar = d.a;
        dVarArr[0] = dVar;
        dVarArr[1] = dVar;
        this.i0 = null;
        this.j0 = 0;
        this.m0 = 0;
        this.n0 = 0;
        float[] fArr = this.o0;
        fArr[0] = -1.0f;
        fArr[1] = -1.0f;
        this.p = -1;
        this.q = -1;
        int[] iArr = this.D;
        iArr[0] = Integer.MAX_VALUE;
        iArr[1] = Integer.MAX_VALUE;
        this.s = 0;
        this.t = 0;
        this.x = 1.0f;
        this.A = 1.0f;
        this.w = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.z = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.v = 0;
        this.y = 0;
        this.B = -1;
        this.C = 1.0f;
        boolean[] zArr = this.f;
        zArr[0] = true;
        zArr[1] = true;
        this.H = false;
        boolean[] zArr2 = this.U;
        zArr2[0] = false;
        zArr2[1] = false;
        this.g = true;
        int[] iArr2 = this.u;
        iArr2[0] = 0;
        iArr2[1] = 0;
        this.h = -1;
        this.i = -1;
    }

    public final void E() {
        e eVar = this.W;
        if (eVar != null && (eVar instanceof f)) {
            ((f) eVar).getClass();
        }
        ArrayList arrayList = this.T;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((c) arrayList.get(i)).j();
        }
    }

    public final void F() {
        this.l = false;
        this.m = false;
        this.n = false;
        this.o = false;
        ArrayList arrayList = this.T;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            c cVar = (c) arrayList.get(i);
            cVar.c = false;
            cVar.b = 0;
        }
    }

    public void G(com.quizlet.data.interactor.set.c cVar) {
        this.K.k();
        this.L.k();
        this.M.k();
        this.N.k();
        this.O.k();
        this.R.k();
        this.P.k();
        this.Q.k();
    }

    public final void J(int i) {
        this.d0 = i;
        this.F = i > 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x0086 A[PHI: r0
  0x0086: PHI (r0v2 int) = (r0v1 int), (r0v0 int), (r0v0 int), (r0v0 int), (r0v0 int), (r0v0 int) binds: [B:46:0x0086, B:36:0x007f, B:24:0x0051, B:26:0x0057, B:28:0x0063, B:30:0x0067] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:39:0x0086 -> B:40:0x0087). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void K(java.lang.String r9) throws java.lang.NumberFormatException {
        /*
            r8 = this;
            r0 = 0
            if (r9 == 0) goto L90
            int r1 = r9.length()
            if (r1 != 0) goto Lb
            goto L90
        Lb:
            int r1 = r9.length()
            r2 = 44
            int r2 = r9.indexOf(r2)
            r3 = 0
            r4 = 1
            r5 = -1
            if (r2 <= 0) goto L39
            int r6 = r1 + (-1)
            if (r2 >= r6) goto L39
            java.lang.String r6 = r9.substring(r3, r2)
            java.lang.String r7 = "W"
            boolean r7 = r6.equalsIgnoreCase(r7)
            if (r7 == 0) goto L2b
            goto L36
        L2b:
            java.lang.String r3 = "H"
            boolean r3 = r6.equalsIgnoreCase(r3)
            if (r3 == 0) goto L35
            r3 = r4
            goto L36
        L35:
            r3 = r5
        L36:
            int r2 = r2 + r4
            r5 = r3
            r3 = r2
        L39:
            r2 = 58
            int r2 = r9.indexOf(r2)
            if (r2 < 0) goto L77
            int r1 = r1 - r4
            if (r2 >= r1) goto L77
            java.lang.String r1 = r9.substring(r3, r2)
            int r2 = r2 + r4
            java.lang.String r9 = r9.substring(r2)
            int r2 = r1.length()
            if (r2 <= 0) goto L86
            int r2 = r9.length()
            if (r2 <= 0) goto L86
            float r1 = java.lang.Float.parseFloat(r1)     // Catch: java.lang.NumberFormatException -> L86
            float r9 = java.lang.Float.parseFloat(r9)     // Catch: java.lang.NumberFormatException -> L86
            int r2 = (r1 > r0 ? 1 : (r1 == r0 ? 0 : -1))
            if (r2 <= 0) goto L86
            int r2 = (r9 > r0 ? 1 : (r9 == r0 ? 0 : -1))
            if (r2 <= 0) goto L86
            if (r5 != r4) goto L71
            float r9 = r9 / r1
            float r9 = java.lang.Math.abs(r9)     // Catch: java.lang.NumberFormatException -> L86
            goto L87
        L71:
            float r1 = r1 / r9
            float r9 = java.lang.Math.abs(r1)     // Catch: java.lang.NumberFormatException -> L86
            goto L87
        L77:
            java.lang.String r9 = r9.substring(r3)
            int r1 = r9.length()
            if (r1 <= 0) goto L86
            float r9 = java.lang.Float.parseFloat(r9)     // Catch: java.lang.NumberFormatException -> L86
            goto L87
        L86:
            r9 = r0
        L87:
            int r0 = (r9 > r0 ? 1 : (r9 == r0 ? 0 : -1))
            if (r0 <= 0) goto L8f
            r8.Z = r9
            r8.a0 = r5
        L8f:
            return
        L90:
            r8.Z = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.e.K(java.lang.String):void");
    }

    public final void L(int i, int i2) {
        if (this.l) {
            return;
        }
        this.K.l(i);
        this.M.l(i2);
        this.b0 = i;
        this.X = i2 - i;
        this.l = true;
    }

    public final void M(int i, int i2) {
        if (this.m) {
            return;
        }
        this.L.l(i);
        this.N.l(i2);
        this.c0 = i;
        this.Y = i2 - i;
        if (this.F) {
            this.O.l(i + this.d0);
        }
        this.m = true;
    }

    public final void N(int i) {
        this.Y = i;
        int i2 = this.f0;
        if (i < i2) {
            this.Y = i2;
        }
    }

    public final void O(d dVar) {
        this.V[0] = dVar;
    }

    public final void P(float f, int i, int i2, int i3) {
        this.s = i;
        this.v = i2;
        if (i3 == Integer.MAX_VALUE) {
            i3 = 0;
        }
        this.w = i3;
        this.x = f;
        if (f <= DefinitionKt.NO_Float_VALUE || f >= 1.0f || i != 0) {
            return;
        }
        this.s = 2;
    }

    public final void Q(d dVar) {
        this.V[1] = dVar;
    }

    public final void R(float f, int i, int i2, int i3) {
        this.t = i;
        this.y = i2;
        if (i3 == Integer.MAX_VALUE) {
            i3 = 0;
        }
        this.z = i3;
        this.A = f;
        if (f <= DefinitionKt.NO_Float_VALUE || f >= 1.0f || i != 0) {
            return;
        }
        this.t = 2;
    }

    public final void S(int i) {
        this.X = i;
        int i2 = this.e0;
        if (i < i2) {
            this.X = i2;
        }
    }

    public void T(boolean z, boolean z2) {
        int i;
        int i2;
        androidx.constraintlayout.core.widgets.analyzer.l lVar = this.d;
        boolean z3 = z & lVar.g;
        n nVar = this.e;
        boolean z4 = z2 & nVar.g;
        int i3 = lVar.h.g;
        int i4 = nVar.h.g;
        int i5 = lVar.i.g;
        int i6 = nVar.i.g;
        int i7 = i6 - i4;
        if (i5 - i3 < 0 || i7 < 0 || i3 == Integer.MIN_VALUE || i3 == Integer.MAX_VALUE || i4 == Integer.MIN_VALUE || i4 == Integer.MAX_VALUE || i5 == Integer.MIN_VALUE || i5 == Integer.MAX_VALUE || i6 == Integer.MIN_VALUE || i6 == Integer.MAX_VALUE) {
            i5 = 0;
            i6 = 0;
            i3 = 0;
            i4 = 0;
        }
        int i8 = i5 - i3;
        int i9 = i6 - i4;
        if (z3) {
            this.b0 = i3;
        }
        if (z4) {
            this.c0 = i4;
        }
        if (this.j0 == 8) {
            this.X = 0;
            this.Y = 0;
            return;
        }
        d dVar = d.a;
        if (z3) {
            if (this.V[0] == dVar && i8 < (i2 = this.X)) {
                i8 = i2;
            }
            this.X = i8;
            int i10 = this.e0;
            if (i8 < i10) {
                this.X = i10;
            }
        }
        if (z4) {
            if (this.V[1] == dVar && i9 < (i = this.Y)) {
                i9 = i;
            }
            this.Y = i9;
            int i11 = this.f0;
            if (i9 < i11) {
                this.Y = i11;
            }
        }
    }

    public void U(androidx.constraintlayout.core.c cVar, boolean z) {
        int i;
        int i2;
        n nVar;
        androidx.constraintlayout.core.widgets.analyzer.l lVar;
        c cVar2 = this.K;
        cVar.getClass();
        int iN = androidx.constraintlayout.core.c.n(cVar2);
        int iN2 = androidx.constraintlayout.core.c.n(this.L);
        int iN3 = androidx.constraintlayout.core.c.n(this.M);
        int iN4 = androidx.constraintlayout.core.c.n(this.N);
        if (z && (lVar = this.d) != null) {
            androidx.constraintlayout.core.widgets.analyzer.g gVar = lVar.h;
            if (gVar.j) {
                androidx.constraintlayout.core.widgets.analyzer.g gVar2 = lVar.i;
                if (gVar2.j) {
                    iN = gVar.g;
                    iN3 = gVar2.g;
                }
            }
        }
        if (z && (nVar = this.e) != null) {
            androidx.constraintlayout.core.widgets.analyzer.g gVar3 = nVar.h;
            if (gVar3.j) {
                androidx.constraintlayout.core.widgets.analyzer.g gVar4 = nVar.i;
                if (gVar4.j) {
                    iN2 = gVar3.g;
                    iN4 = gVar4.g;
                }
            }
        }
        int i3 = iN4 - iN2;
        if (iN3 - iN < 0 || i3 < 0 || iN == Integer.MIN_VALUE || iN == Integer.MAX_VALUE || iN2 == Integer.MIN_VALUE || iN2 == Integer.MAX_VALUE || iN3 == Integer.MIN_VALUE || iN3 == Integer.MAX_VALUE || iN4 == Integer.MIN_VALUE || iN4 == Integer.MAX_VALUE) {
            iN = 0;
            iN2 = 0;
            iN3 = 0;
            iN4 = 0;
        }
        int i4 = iN3 - iN;
        int i5 = iN4 - iN2;
        this.b0 = iN;
        this.c0 = iN2;
        if (this.j0 == 8) {
            this.X = 0;
            this.Y = 0;
            return;
        }
        d[] dVarArr = this.V;
        d dVar = dVarArr[0];
        d dVar2 = d.a;
        if (dVar == dVar2 && i4 < (i2 = this.X)) {
            i4 = i2;
        }
        if (dVarArr[1] == dVar2 && i5 < (i = this.Y)) {
            i5 = i;
        }
        this.X = i4;
        this.Y = i5;
        int i6 = this.f0;
        if (i5 < i6) {
            this.Y = i6;
        }
        int i7 = this.e0;
        if (i4 < i7) {
            this.X = i7;
        }
        int i8 = this.w;
        d dVar3 = d.c;
        if (i8 > 0 && dVar == dVar3) {
            this.X = Math.min(this.X, i8);
        }
        int i9 = this.z;
        if (i9 > 0 && this.V[1] == dVar3) {
            this.Y = Math.min(this.Y, i9);
        }
        int i10 = this.X;
        if (i4 != i10) {
            this.h = i10;
        }
        int i11 = this.Y;
        if (i5 != i11) {
            this.i = i11;
        }
    }

    public final void a() {
        c cVar = this.K;
        ArrayList arrayList = this.T;
        arrayList.add(cVar);
        arrayList.add(this.L);
        arrayList.add(this.M);
        arrayList.add(this.N);
        arrayList.add(this.P);
        arrayList.add(this.Q);
        arrayList.add(this.R);
        arrayList.add(this.O);
    }

    public final void b(f fVar, androidx.constraintlayout.core.c cVar, HashSet hashSet, int i, boolean z) {
        if (z) {
            if (!hashSet.contains(this)) {
                return;
            }
            k.b(fVar, cVar, this);
            hashSet.remove(this);
            c(cVar, fVar.c0(64));
        }
        if (i == 0) {
            HashSet hashSet2 = this.K.a;
            if (hashSet2 != null) {
                Iterator it2 = hashSet2.iterator();
                while (it2.hasNext()) {
                    ((c) it2.next()).d.b(fVar, cVar, hashSet, i, true);
                }
            }
            HashSet hashSet3 = this.M.a;
            if (hashSet3 != null) {
                Iterator it3 = hashSet3.iterator();
                while (it3.hasNext()) {
                    ((c) it3.next()).d.b(fVar, cVar, hashSet, i, true);
                }
                return;
            }
            return;
        }
        HashSet hashSet4 = this.L.a;
        if (hashSet4 != null) {
            Iterator it4 = hashSet4.iterator();
            while (it4.hasNext()) {
                ((c) it4.next()).d.b(fVar, cVar, hashSet, i, true);
            }
        }
        HashSet hashSet5 = this.N.a;
        if (hashSet5 != null) {
            Iterator it5 = hashSet5.iterator();
            while (it5.hasNext()) {
                ((c) it5.next()).d.b(fVar, cVar, hashSet, i, true);
            }
        }
        HashSet hashSet6 = this.O.a;
        if (hashSet6 != null) {
            Iterator it6 = hashSet6.iterator();
            while (it6.hasNext()) {
                ((c) it6.next()).d.b(fVar, cVar, hashSet, i, true);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0210  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0218  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x0293  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x029e  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x02a7  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x02ba  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x02c8  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x02cd  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x02ec  */
    /* JADX WARN: Removed duplicated region for block: B:276:0x03f9  */
    /* JADX WARN: Removed duplicated region for block: B:280:0x040f  */
    /* JADX WARN: Removed duplicated region for block: B:285:0x041a  */
    /* JADX WARN: Removed duplicated region for block: B:288:0x0420  */
    /* JADX WARN: Removed duplicated region for block: B:292:0x042a  */
    /* JADX WARN: Removed duplicated region for block: B:295:0x0434  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x043a  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x043d  */
    /* JADX WARN: Removed duplicated region for block: B:303:0x0456  */
    /* JADX WARN: Removed duplicated region for block: B:322:0x049d  */
    /* JADX WARN: Removed duplicated region for block: B:337:0x054b  */
    /* JADX WARN: Removed duplicated region for block: B:353:0x059c  */
    /* JADX WARN: Removed duplicated region for block: B:356:0x05ac  */
    /* JADX WARN: Removed duplicated region for block: B:357:0x05ae  */
    /* JADX WARN: Removed duplicated region for block: B:360:0x05b2  */
    /* JADX WARN: Removed duplicated region for block: B:382:0x05ea  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x0670  */
    /* JADX WARN: Removed duplicated region for block: B:399:0x0676  */
    /* JADX WARN: Removed duplicated region for block: B:405:0x06d4  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0109  */
    /* JADX WARN: Type inference failed for: r12v36 */
    /* JADX WARN: Type inference failed for: r12v37, types: [int] */
    /* JADX WARN: Type inference failed for: r12v42 */
    /* JADX WARN: Type inference failed for: r14v47, types: [androidx.constraintlayout.core.widgets.f] */
    /* JADX WARN: Type inference failed for: r18v14 */
    /* JADX WARN: Type inference failed for: r18v15 */
    /* JADX WARN: Type inference failed for: r18v18 */
    /* JADX WARN: Type inference failed for: r18v2 */
    /* JADX WARN: Type inference failed for: r18v9, types: [boolean] */
    /* JADX WARN: Type inference failed for: r20v11 */
    /* JADX WARN: Type inference failed for: r20v13 */
    /* JADX WARN: Type inference failed for: r20v14 */
    /* JADX WARN: Type inference failed for: r20v2 */
    /* JADX WARN: Type inference failed for: r27v3 */
    /* JADX WARN: Type inference failed for: r27v4, types: [boolean] */
    /* JADX WARN: Type inference failed for: r27v7 */
    /* JADX WARN: Type inference failed for: r27v8 */
    /* JADX WARN: Type inference failed for: r27v9 */
    /* JADX WARN: Type inference failed for: r60v0, types: [androidx.constraintlayout.core.widgets.e] */
    /* JADX WARN: Type inference failed for: r9v12, types: [boolean] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c(androidx.constraintlayout.core.c r61, boolean r62) {
        /*
            Method dump skipped, instructions count: 1927
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.e.c(androidx.constraintlayout.core.c, boolean):void");
    }

    public boolean d() {
        return this.j0 != 8;
    }

    /* JADX WARN: Removed duplicated region for block: B:217:0x03bb A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:220:0x03c4  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x03c8  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0401  */
    /* JADX WARN: Removed duplicated region for block: B:240:0x041e  */
    /* JADX WARN: Removed duplicated region for block: B:257:0x0451  */
    /* JADX WARN: Removed duplicated region for block: B:259:0x0457  */
    /* JADX WARN: Removed duplicated region for block: B:287:0x0492 A[PHI: r3
  0x0492: PHI (r3v16 int) = (r3v15 int), (r3v20 int), (r3v20 int), (r3v20 int) binds: [B:280:0x0482, B:282:0x0488, B:283:0x048a, B:285:0x048e] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:290:0x04a4  */
    /* JADX WARN: Removed duplicated region for block: B:303:0x04c5  */
    /* JADX WARN: Removed duplicated region for block: B:308:0x04d3 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:337:0x0522  */
    /* JADX WARN: Removed duplicated region for block: B:345:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(androidx.constraintlayout.core.c r30, boolean r31, boolean r32, boolean r33, boolean r34, androidx.constraintlayout.core.g r35, androidx.constraintlayout.core.g r36, androidx.constraintlayout.core.widgets.d r37, boolean r38, androidx.constraintlayout.core.widgets.c r39, androidx.constraintlayout.core.widgets.c r40, int r41, int r42, int r43, int r44, float r45, boolean r46, boolean r47, boolean r48, boolean r49, boolean r50, int r51, int r52, int r53, int r54, float r55, boolean r56) {
        /*
            Method dump skipped, instructions count: 1324
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.e.e(androidx.constraintlayout.core.c, boolean, boolean, boolean, boolean, androidx.constraintlayout.core.g, androidx.constraintlayout.core.g, androidx.constraintlayout.core.widgets.d, boolean, androidx.constraintlayout.core.widgets.c, androidx.constraintlayout.core.widgets.c, int, int, int, int, float, boolean, boolean, boolean, boolean, boolean, int, int, int, int, float, boolean):void");
    }

    public final void f(int i, e eVar, int i2, int i3) {
        boolean z;
        if (i == 7) {
            if (i2 != 7) {
                if (i2 == 2 || i2 == 4) {
                    f(2, eVar, i2, 0);
                    f(4, eVar, i2, 0);
                    j(7).a(eVar.j(i2), 0);
                    return;
                } else {
                    if (i2 == 3 || i2 == 5) {
                        f(3, eVar, i2, 0);
                        f(5, eVar, i2, 0);
                        j(7).a(eVar.j(i2), 0);
                        return;
                    }
                    return;
                }
            }
            c cVarJ = j(2);
            c cVarJ2 = j(4);
            c cVarJ3 = j(3);
            c cVarJ4 = j(5);
            boolean z2 = true;
            if ((cVarJ == null || !cVarJ.h()) && (cVarJ2 == null || !cVarJ2.h())) {
                f(2, eVar, 2, 0);
                f(4, eVar, 4, 0);
                z = true;
            } else {
                z = false;
            }
            if ((cVarJ3 == null || !cVarJ3.h()) && (cVarJ4 == null || !cVarJ4.h())) {
                f(3, eVar, 3, 0);
                f(5, eVar, 5, 0);
            } else {
                z2 = false;
            }
            if (z && z2) {
                j(7).a(eVar.j(7), 0);
                return;
            } else if (z) {
                j(8).a(eVar.j(8), 0);
                return;
            } else {
                if (z2) {
                    j(9).a(eVar.j(9), 0);
                    return;
                }
                return;
            }
        }
        if (i == 8 && (i2 == 2 || i2 == 4)) {
            c cVarJ5 = j(2);
            c cVarJ6 = eVar.j(i2);
            c cVarJ7 = j(4);
            cVarJ5.a(cVarJ6, 0);
            cVarJ7.a(cVarJ6, 0);
            j(8).a(cVarJ6, 0);
            return;
        }
        if (i == 9 && (i2 == 3 || i2 == 5)) {
            c cVarJ8 = eVar.j(i2);
            j(3).a(cVarJ8, 0);
            j(5).a(cVarJ8, 0);
            j(9).a(cVarJ8, 0);
            return;
        }
        if (i == 8 && i2 == 8) {
            j(2).a(eVar.j(2), 0);
            j(4).a(eVar.j(4), 0);
            j(8).a(eVar.j(i2), 0);
            return;
        }
        if (i == 9 && i2 == 9) {
            j(3).a(eVar.j(3), 0);
            j(5).a(eVar.j(5), 0);
            j(9).a(eVar.j(i2), 0);
            return;
        }
        c cVarJ9 = j(i);
        c cVarJ10 = eVar.j(i2);
        if (cVarJ9.i(cVarJ10)) {
            if (i == 6) {
                c cVarJ11 = j(3);
                c cVarJ12 = j(5);
                if (cVarJ11 != null) {
                    cVarJ11.j();
                }
                if (cVarJ12 != null) {
                    cVarJ12.j();
                }
            } else if (i == 3 || i == 5) {
                c cVarJ13 = j(6);
                if (cVarJ13 != null) {
                    cVarJ13.j();
                }
                c cVarJ14 = j(7);
                if (cVarJ14.f != cVarJ10) {
                    cVarJ14.j();
                }
                c cVarF = j(i).f();
                c cVarJ15 = j(9);
                if (cVarJ15.h()) {
                    cVarF.j();
                    cVarJ15.j();
                }
            } else if (i == 2 || i == 4) {
                c cVarJ16 = j(7);
                if (cVarJ16.f != cVarJ10) {
                    cVarJ16.j();
                }
                c cVarF2 = j(i).f();
                c cVarJ17 = j(8);
                if (cVarJ17.h()) {
                    cVarF2.j();
                    cVarJ17.j();
                }
            }
            cVarJ9.a(cVarJ10, i3);
        }
    }

    public final void g(c cVar, c cVar2, int i) {
        if (cVar.d == this) {
            f(cVar.e, cVar2.d, cVar2.e, i);
        }
    }

    public final void h(androidx.constraintlayout.core.c cVar) {
        cVar.k(this.K);
        cVar.k(this.L);
        cVar.k(this.M);
        cVar.k(this.N);
        if (this.d0 > 0) {
            cVar.k(this.O);
        }
    }

    public final void i() {
        if (this.d == null) {
            androidx.constraintlayout.core.widgets.analyzer.l lVar = new androidx.constraintlayout.core.widgets.analyzer.l(this);
            lVar.h.e = 4;
            lVar.i.e = 5;
            lVar.f = 0;
            this.d = lVar;
        }
        if (this.e == null) {
            n nVar = new n(this);
            androidx.constraintlayout.core.widgets.analyzer.g gVar = new androidx.constraintlayout.core.widgets.analyzer.g(nVar);
            nVar.k = gVar;
            nVar.l = null;
            nVar.h.e = 6;
            nVar.i.e = 7;
            gVar.e = 8;
            nVar.f = 1;
            this.e = nVar;
        }
    }

    public c j(int i) {
        switch (AbstractC0147y.k(i)) {
            case 0:
                return null;
            case 1:
                return this.K;
            case 2:
                return this.L;
            case 3:
                return this.M;
            case 4:
                return this.N;
            case 5:
                return this.O;
            case 6:
                return this.R;
            case 7:
                return this.P;
            case 8:
                return this.Q;
            default:
                throw new AssertionError(B.v(i));
        }
    }

    public final d k(int i) {
        if (i == 0) {
            return this.V[0];
        }
        if (i == 1) {
            return this.V[1];
        }
        return null;
    }

    public final int l() {
        if (this.j0 == 8) {
            return 0;
        }
        return this.Y;
    }

    public final e m(int i) {
        c cVar;
        c cVar2;
        if (i != 0) {
            if (i == 1 && (cVar2 = (cVar = this.N).f) != null && cVar2.f == cVar) {
                return cVar2.d;
            }
            return null;
        }
        c cVar3 = this.M;
        c cVar4 = cVar3.f;
        if (cVar4 == null || cVar4.f != cVar3) {
            return null;
        }
        return cVar4.d;
    }

    public final e n(int i) {
        c cVar;
        c cVar2;
        if (i != 0) {
            if (i == 1 && (cVar2 = (cVar = this.L).f) != null && cVar2.f == cVar) {
                return cVar2.d;
            }
            return null;
        }
        c cVar3 = this.K;
        c cVar4 = cVar3.f;
        if (cVar4 == null || cVar4.f != cVar3) {
            return null;
        }
        return cVar4.d;
    }

    public void o(StringBuilder sb) {
        sb.append("  " + this.k + ":{\n");
        StringBuilder sb2 = new StringBuilder("    actualWidth:");
        sb2.append(this.X);
        sb.append(sb2.toString());
        sb.append("\n");
        sb.append("    actualHeight:" + this.Y);
        sb.append("\n");
        sb.append("    actualLeft:" + this.b0);
        sb.append("\n");
        sb.append("    actualTop:" + this.c0);
        sb.append("\n");
        q(sb, "left", this.K);
        q(sb, "top", this.L);
        q(sb, "right", this.M);
        q(sb, "bottom", this.N);
        q(sb, "baseline", this.O);
        q(sb, "centerX", this.P);
        q(sb, "centerY", this.Q);
        int i = this.X;
        int i2 = this.e0;
        int i3 = this.D[0];
        int i4 = this.v;
        int i5 = this.s;
        float f = this.x;
        d dVar = this.V[0];
        float[] fArr = this.o0;
        float f2 = fArr[0];
        p(sb, "    width", i, i2, i3, i4, i5, f, dVar);
        int i6 = this.Y;
        int i7 = this.f0;
        int i8 = this.D[1];
        int i9 = this.y;
        int i10 = this.t;
        float f3 = this.A;
        d dVar2 = this.V[1];
        float f4 = fArr[1];
        p(sb, "    height", i6, i7, i8, i9, i10, f3, dVar2);
        float f5 = this.Z;
        int i11 = this.a0;
        if (f5 != DefinitionKt.NO_Float_VALUE) {
            sb.append("    dimensionRatio");
            sb.append(" :  [");
            sb.append(f5);
            sb.append(",");
            sb.append(i11);
            sb.append("");
            sb.append("],\n");
        }
        I(sb, "    horizontalBias", this.g0, 0.5f);
        I(sb, "    verticalBias", this.h0, 0.5f);
        H(this.m0, 0, "    horizontalChainStyle", sb);
        H(this.n0, 0, "    verticalChainStyle", sb);
        sb.append("  }");
    }

    public final int r() {
        if (this.j0 == 8) {
            return 0;
        }
        return this.X;
    }

    public final int s() {
        e eVar = this.W;
        return (eVar == null || !(eVar instanceof f)) ? this.b0 : ((f) eVar).A0 + this.b0;
    }

    public final int t() {
        e eVar = this.W;
        return (eVar == null || !(eVar instanceof f)) ? this.c0 : ((f) eVar).B0 + this.c0;
    }

    public String toString() {
        StringBuilder sbU = d0.u("");
        sbU.append(this.l0 != null ? android.support.v4.media.session.a.t(new StringBuilder("id: "), this.l0, " ") : "");
        sbU.append("(");
        sbU.append(this.b0);
        sbU.append(", ");
        sbU.append(this.c0);
        sbU.append(") - (");
        sbU.append(this.X);
        sbU.append(" x ");
        return android.support.v4.media.session.a.r(sbU, this.Y, ")");
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x003a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x003b A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean u(int r5) {
        /*
            r4 = this;
            r0 = 2
            r1 = 0
            r2 = 1
            if (r5 != 0) goto L1b
            androidx.constraintlayout.core.widgets.c r5 = r4.K
            androidx.constraintlayout.core.widgets.c r5 = r5.f
            if (r5 == 0) goto Ld
            r5 = r2
            goto Le
        Ld:
            r5 = r1
        Le:
            androidx.constraintlayout.core.widgets.c r3 = r4.M
            androidx.constraintlayout.core.widgets.c r3 = r3.f
            if (r3 == 0) goto L16
            r3 = r2
            goto L17
        L16:
            r3 = r1
        L17:
            int r5 = r5 + r3
            if (r5 >= r0) goto L3b
            goto L3a
        L1b:
            androidx.constraintlayout.core.widgets.c r5 = r4.L
            androidx.constraintlayout.core.widgets.c r5 = r5.f
            if (r5 == 0) goto L23
            r5 = r2
            goto L24
        L23:
            r5 = r1
        L24:
            androidx.constraintlayout.core.widgets.c r3 = r4.N
            androidx.constraintlayout.core.widgets.c r3 = r3.f
            if (r3 == 0) goto L2c
            r3 = r2
            goto L2d
        L2c:
            r3 = r1
        L2d:
            int r5 = r5 + r3
            androidx.constraintlayout.core.widgets.c r3 = r4.O
            androidx.constraintlayout.core.widgets.c r3 = r3.f
            if (r3 == 0) goto L36
            r3 = r2
            goto L37
        L36:
            r3 = r1
        L37:
            int r5 = r5 + r3
            if (r5 >= r0) goto L3b
        L3a:
            return r2
        L3b:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.e.u(int):boolean");
    }

    public final boolean v(int i, int i2) {
        c cVar;
        c cVar2;
        c cVar3;
        c cVar4;
        if (i == 0) {
            c cVar5 = this.K;
            c cVar6 = cVar5.f;
            if (cVar6 == null || !cVar6.c || (cVar4 = (cVar3 = this.M).f) == null || !cVar4.c) {
                return false;
            }
            return (cVar4.d() - cVar3.e()) - (cVar5.e() + cVar5.f.d()) >= i2;
        }
        c cVar7 = this.L;
        c cVar8 = cVar7.f;
        if (cVar8 == null || !cVar8.c || (cVar2 = (cVar = this.N).f) == null || !cVar2.c) {
            return false;
        }
        return (cVar2.d() - cVar.e()) - (cVar7.e() + cVar7.f.d()) >= i2;
    }

    public final void w(int i, int i2, int i3, int i4, e eVar) {
        j(i).b(eVar.j(i2), i3, i4, true);
    }

    public final boolean x(int i) {
        c cVar;
        c cVar2;
        int i2 = i * 2;
        c[] cVarArr = this.S;
        c cVar3 = cVarArr[i2];
        c cVar4 = cVar3.f;
        return (cVar4 == null || cVar4.f == cVar3 || (cVar2 = (cVar = cVarArr[i2 + 1]).f) == null || cVar2.f != cVar) ? false : true;
    }

    public final boolean y() {
        c cVar = this.K;
        c cVar2 = cVar.f;
        if (cVar2 != null && cVar2.f == cVar) {
            return true;
        }
        c cVar3 = this.M;
        c cVar4 = cVar3.f;
        return cVar4 != null && cVar4.f == cVar3;
    }

    public final boolean z() {
        c cVar = this.L;
        c cVar2 = cVar.f;
        if (cVar2 != null && cVar2.f == cVar) {
            return true;
        }
        c cVar3 = this.N;
        c cVar4 = cVar3.f;
        return cVar4 != null && cVar4.f == cVar3;
    }

    public e(int i, int i2) {
        this.a = false;
        this.d = null;
        this.e = null;
        this.f = new boolean[]{true, true};
        this.g = true;
        this.h = -1;
        this.i = -1;
        this.j = new androidx.constraintlayout.core.state.k(this);
        this.l = false;
        this.m = false;
        this.n = false;
        this.o = false;
        this.p = -1;
        this.q = -1;
        this.r = 0;
        this.s = 0;
        this.t = 0;
        this.u = new int[2];
        this.v = 0;
        this.w = 0;
        this.x = 1.0f;
        this.y = 0;
        this.z = 0;
        this.A = 1.0f;
        this.B = -1;
        this.C = 1.0f;
        this.D = new int[]{SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO};
        this.E = Float.NaN;
        this.F = false;
        this.H = false;
        this.I = 0;
        this.J = 0;
        c cVar = new c(this, 2);
        this.K = cVar;
        c cVar2 = new c(this, 3);
        this.L = cVar2;
        c cVar3 = new c(this, 4);
        this.M = cVar3;
        c cVar4 = new c(this, 5);
        this.N = cVar4;
        c cVar5 = new c(this, 6);
        this.O = cVar5;
        this.P = new c(this, 8);
        this.Q = new c(this, 9);
        c cVar6 = new c(this, 7);
        this.R = cVar6;
        this.S = new c[]{cVar, cVar3, cVar2, cVar4, cVar5, cVar6};
        this.T = new ArrayList();
        this.U = new boolean[2];
        d dVar = d.a;
        this.V = new d[]{dVar, dVar};
        this.W = null;
        this.Z = DefinitionKt.NO_Float_VALUE;
        this.a0 = -1;
        this.d0 = 0;
        this.g0 = 0.5f;
        this.h0 = 0.5f;
        this.j0 = 0;
        this.k0 = false;
        this.l0 = null;
        this.m0 = 0;
        this.n0 = 0;
        this.o0 = new float[]{-1.0f, -1.0f};
        this.p0 = new e[]{null, null};
        this.q0 = new e[]{null, null};
        this.r0 = -1;
        this.s0 = -1;
        this.b0 = 0;
        this.c0 = 0;
        this.X = i;
        this.Y = i2;
        a();
    }
}
