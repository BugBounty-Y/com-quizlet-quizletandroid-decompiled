package androidx.constraintlayout.core.utils;

import androidx.camera.camera2.internal.a0;
import androidx.constraintlayout.core.widgets.d;
import androidx.constraintlayout.core.widgets.e;
import androidx.constraintlayout.core.widgets.f;
import androidx.constraintlayout.core.widgets.l;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class a extends l {
    public f G0;
    public e[] H0;
    public boolean I0;
    public int J0;
    public int K0;
    public int L0;
    public int M0;
    public float N0;
    public float O0;
    public String P0;
    public String Q0;
    public String R0;
    public String S0;
    public int T0;
    public int U0;
    public boolean[][] V0;
    public HashSet W0;
    public int[][] X0;
    public int Y0;
    public int[][] Z0;
    public int a1;

    public static void a0(e eVar) {
        eVar.o0[1] = -1.0f;
        eVar.L.j();
        eVar.N.j();
        eVar.O.j();
    }

    public static float[] j0(int i, String str) {
        if (str == null || str.trim().isEmpty()) {
            return null;
        }
        String[] strArrSplit = str.split(",");
        float[] fArr = new float[i];
        for (int i2 = 0; i2 < i; i2++) {
            if (i2 < strArrSplit.length) {
                try {
                    fArr[i2] = Float.parseFloat(strArrSplit[i2]);
                } catch (Exception e) {
                    System.err.println("Error parsing `" + strArrSplit[i2] + "`: " + e.getMessage());
                    fArr[i2] = 1.0f;
                }
            } else {
                fArr[i2] = 1.0f;
            }
        }
        return fArr;
    }

    @Override // androidx.constraintlayout.core.widgets.l
    public final void Y(int i, int i2, int i3, int i4) {
        int[][] iArrI0;
        this.G0 = (f) this.W;
        if (this.J0 >= 1 && this.L0 >= 1) {
            this.U0 = 0;
            String str = this.S0;
            if (str != null && !str.trim().isEmpty() && (iArrI0 = i0(this.S0, false)) != null) {
                e0(iArrI0);
            }
            String str2 = this.R0;
            if (str2 != null && !str2.trim().isEmpty()) {
                this.Z0 = i0(this.R0, true);
            }
            int iMax = Math.max(this.J0, this.L0);
            e[] eVarArr = this.H0;
            d dVar = d.c;
            if (eVarArr == null) {
                this.H0 = new e[iMax];
                int i5 = 0;
                while (true) {
                    e[] eVarArr2 = this.H0;
                    if (i5 >= eVarArr2.length) {
                        break;
                    }
                    e eVar = new e();
                    d[] dVarArr = eVar.V;
                    dVarArr[0] = dVar;
                    dVarArr[1] = dVar;
                    eVar.k = String.valueOf(eVar.hashCode());
                    eVarArr2[i5] = eVar;
                    i5++;
                }
            } else if (iMax != eVarArr.length) {
                e[] eVarArr3 = new e[iMax];
                for (int i6 = 0; i6 < iMax; i6++) {
                    e[] eVarArr4 = this.H0;
                    if (i6 < eVarArr4.length) {
                        eVarArr3[i6] = eVarArr4[i6];
                    } else {
                        e eVar2 = new e();
                        d[] dVarArr2 = eVar2.V;
                        dVarArr2[0] = dVar;
                        dVarArr2[1] = dVar;
                        eVar2.k = String.valueOf(eVar2.hashCode());
                        eVarArr3[i6] = eVar2;
                    }
                }
                while (true) {
                    e[] eVarArr5 = this.H0;
                    if (iMax >= eVarArr5.length) {
                        break;
                    }
                    e eVar3 = eVarArr5[iMax];
                    this.G0.t0.remove(eVar3);
                    eVar3.D();
                    iMax++;
                }
                this.H0 = eVarArr3;
            }
            int[][] iArr = this.Z0;
            if (iArr != null) {
                f0(iArr);
            }
        }
        f fVar = this.G0;
        e[] eVarArr6 = this.H0;
        fVar.getClass();
        for (e eVar4 : eVarArr6) {
            fVar.V(eVar4);
        }
    }

    public final void b0(int i, int i2, int i3, int i4, e eVar) {
        eVar.K.a(this.H0[i2].K, 0);
        eVar.L.a(this.H0[i].L, 0);
        eVar.M.a(this.H0[(i2 + i4) - 1].M, 0);
        eVar.N.a(this.H0[(i + i3) - 1].N, 0);
    }

    /* JADX WARN: Removed duplicated region for block: B:77:0x01c0  */
    @Override // androidx.constraintlayout.core.widgets.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.constraintlayout.core.c r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 463
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.utils.a.c(androidx.constraintlayout.core.c, boolean):void");
    }

    public final int c0(int i) {
        return this.T0 == 1 ? i / this.J0 : i % this.L0;
    }

    public final int d0(int i) {
        return this.T0 == 1 ? i % this.J0 : i / this.L0;
    }

    public final void e0(int[][] iArr) {
        for (int[] iArr2 : iArr) {
            if (!h0(d0(iArr2[0]), c0(iArr2[0]), iArr2[1], iArr2[2])) {
                return;
            }
        }
    }

    public final void f0(int[][] iArr) {
        if ((this.Y0 & 2) > 0) {
            return;
        }
        for (int i = 0; i < iArr.length; i++) {
            int iD0 = d0(iArr[i][0]);
            int iC0 = c0(iArr[i][0]);
            int[] iArr2 = iArr[i];
            if (!h0(iD0, iC0, iArr2[1], iArr2[2])) {
                break;
            }
            e eVar = this.t0[i];
            int[] iArr3 = iArr[i];
            b0(iD0, iC0, iArr3[1], iArr3[2], eVar);
            this.W0.add(this.t0[i].k);
        }
    }

    public final void g0() {
        boolean[][] zArr = (boolean[][]) Array.newInstance((Class<?>) Boolean.TYPE, this.J0, this.L0);
        this.V0 = zArr;
        for (boolean[] zArr2 : zArr) {
            Arrays.fill(zArr2, true);
        }
        int i = this.u0;
        if (i > 0) {
            int[][] iArr = (int[][]) Array.newInstance((Class<?>) Integer.TYPE, i, 4);
            this.X0 = iArr;
            for (int[] iArr2 : iArr) {
                Arrays.fill(iArr2, -1);
            }
        }
    }

    public final boolean h0(int i, int i2, int i3, int i4) {
        for (int i5 = i; i5 < i + i3; i5++) {
            for (int i6 = i2; i6 < i2 + i4; i6++) {
                boolean[][] zArr = this.V0;
                if (i5 < zArr.length && i6 < zArr[0].length) {
                    boolean[] zArr2 = zArr[i5];
                    if (zArr2[i6]) {
                        zArr2[i6] = false;
                    }
                }
                return false;
            }
        }
        return true;
    }

    public final int[][] i0(String str, boolean z) {
        int i;
        int i2;
        try {
            String[] strArrSplit = str.split(",");
            Arrays.sort(strArrSplit, new a0(6));
            int[][] iArr = (int[][]) Array.newInstance((Class<?>) Integer.TYPE, strArrSplit.length, 3);
            if (this.J0 != 1 && this.L0 != 1) {
                for (int i3 = 0; i3 < strArrSplit.length; i3++) {
                    String[] strArrSplit2 = strArrSplit[i3].trim().split(":");
                    String[] strArrSplit3 = strArrSplit2[1].split("x");
                    iArr[i3][0] = Integer.parseInt(strArrSplit2[0]);
                    if ((this.Y0 & 1) > 0) {
                        iArr[i3][1] = Integer.parseInt(strArrSplit3[1]);
                        iArr[i3][2] = Integer.parseInt(strArrSplit3[0]);
                    } else {
                        iArr[i3][1] = Integer.parseInt(strArrSplit3[0]);
                        iArr[i3][2] = Integer.parseInt(strArrSplit3[1]);
                    }
                }
                return iArr;
            }
            int i4 = 0;
            int i5 = 0;
            for (int i6 = 0; i6 < strArrSplit.length; i6++) {
                String[] strArrSplit4 = strArrSplit[i6].trim().split(":");
                iArr[i6][0] = Integer.parseInt(strArrSplit4[0]);
                int[] iArr2 = iArr[i6];
                iArr2[1] = 1;
                iArr2[2] = 1;
                if (this.L0 == 1) {
                    iArr2[1] = Integer.parseInt(strArrSplit4[1]);
                    i4 += iArr[i6][1];
                    if (z) {
                        i4--;
                    }
                }
                if (this.J0 == 1) {
                    iArr[i6][2] = Integer.parseInt(strArrSplit4[1]);
                    i5 += iArr[i6][2];
                    if (z) {
                        i5--;
                    }
                }
            }
            if (i4 != 0 && !this.I0 && (i2 = this.J0 + i4) <= 50 && this.K0 != i2) {
                this.K0 = i2;
                k0();
                g0();
            }
            if (i5 != 0 && !this.I0 && (i = this.L0 + i5) <= 50 && this.M0 != i) {
                this.M0 = i;
                k0();
                g0();
            }
            this.I0 = true;
            return iArr;
        } catch (Exception unused) {
            return null;
        }
    }

    public final void k0() {
        int i;
        int i2 = this.K0;
        if (i2 != 0 && (i = this.M0) != 0) {
            this.J0 = i2;
            this.L0 = i;
            return;
        }
        int i3 = this.M0;
        if (i3 > 0) {
            this.L0 = i3;
            this.J0 = ((this.u0 + i3) - 1) / i3;
        } else if (i2 > 0) {
            this.J0 = i2;
            this.L0 = ((this.u0 + i2) - 1) / i2;
        } else {
            int iSqrt = (int) (Math.sqrt(this.u0) + 1.5d);
            this.J0 = iSqrt;
            this.L0 = ((this.u0 + iSqrt) - 1) / iSqrt;
        }
    }
}
