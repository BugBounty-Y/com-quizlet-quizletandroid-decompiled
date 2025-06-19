package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import androidx.constraintlayout.core.widgets.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class f extends androidx.constraintlayout.core.state.g {
    public String A0;
    public int B0;
    public androidx.constraintlayout.core.utils.a n0;
    public int o0;
    public int p0;
    public int q0;
    public int r0;
    public int s0;
    public int t0;
    public int u0;
    public float v0;
    public float w0;
    public String x0;
    public String y0;
    public String z0;

    public f(k kVar, int i) {
        super(kVar, i);
        this.o0 = 0;
        this.p0 = 0;
        this.q0 = 0;
        this.r0 = 0;
        if (i == 10) {
            this.t0 = 1;
        } else if (i == 11) {
            this.u0 = 1;
        }
    }

    @Override // androidx.constraintlayout.core.state.g, androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final void apply() {
        s();
        androidx.constraintlayout.core.utils.a aVar = this.n0;
        int i = this.s0;
        aVar.getClass();
        if ((i == 0 || i == 1) && aVar.T0 != i) {
            aVar.T0 = i;
        }
        int i2 = this.t0;
        if (i2 != 0) {
            androidx.constraintlayout.core.utils.a aVar2 = this.n0;
            if (i2 > 50) {
                aVar2.getClass();
            } else if (aVar2.K0 != i2) {
                aVar2.K0 = i2;
                aVar2.k0();
                aVar2.g0();
            }
        }
        int i3 = this.u0;
        if (i3 != 0) {
            androidx.constraintlayout.core.utils.a aVar3 = this.n0;
            if (i3 > 50) {
                aVar3.getClass();
            } else if (aVar3.M0 != i3) {
                aVar3.M0 = i3;
                aVar3.k0();
                aVar3.g0();
            }
        }
        float f = this.v0;
        if (f != DefinitionKt.NO_Float_VALUE) {
            androidx.constraintlayout.core.utils.a aVar4 = this.n0;
            if (f < DefinitionKt.NO_Float_VALUE) {
                aVar4.getClass();
            } else if (aVar4.N0 != f) {
                aVar4.N0 = f;
            }
        }
        float f2 = this.w0;
        if (f2 != DefinitionKt.NO_Float_VALUE) {
            androidx.constraintlayout.core.utils.a aVar5 = this.n0;
            if (f2 < DefinitionKt.NO_Float_VALUE) {
                aVar5.getClass();
            } else if (aVar5.O0 != f2) {
                aVar5.O0 = f2;
            }
        }
        String str = this.x0;
        if (str != null && !str.isEmpty()) {
            androidx.constraintlayout.core.utils.a aVar6 = this.n0;
            String str2 = this.x0;
            String str3 = aVar6.P0;
            if (str3 == null || !str3.equals(str2)) {
                aVar6.P0 = str2;
            }
        }
        String str4 = this.y0;
        if (str4 != null && !str4.isEmpty()) {
            androidx.constraintlayout.core.utils.a aVar7 = this.n0;
            String str5 = this.y0;
            String str6 = aVar7.Q0;
            if (str6 == null || !str6.equals(str5)) {
                aVar7.Q0 = str5;
            }
        }
        String str7 = this.z0;
        if (str7 != null && !str7.isEmpty()) {
            androidx.constraintlayout.core.utils.a aVar8 = this.n0;
            String str8 = this.z0;
            String str9 = aVar8.R0;
            if (str9 == null || !str9.equals(str8.toString())) {
                aVar8.I0 = false;
                aVar8.R0 = str8.toString();
            }
        }
        String str10 = this.A0;
        if (str10 != null && !str10.isEmpty()) {
            androidx.constraintlayout.core.utils.a aVar9 = this.n0;
            String str11 = this.A0;
            String str12 = aVar9.S0;
            if (str12 == null || !str12.equals(str11)) {
                aVar9.I0 = false;
                aVar9.S0 = str11;
            }
        }
        androidx.constraintlayout.core.utils.a aVar10 = this.n0;
        aVar10.Y0 = this.B0;
        int i4 = this.o0;
        aVar10.x0 = i4;
        aVar10.z0 = i4;
        aVar10.A0 = i4;
        aVar10.y0 = this.p0;
        aVar10.v0 = this.q0;
        aVar10.w0 = this.r0;
        r();
    }

    @Override // androidx.constraintlayout.core.state.g
    public final j s() {
        int[][] iArrI0;
        int[][] iArrI02;
        boolean[][] zArr;
        if (this.n0 == null) {
            androidx.constraintlayout.core.utils.a aVar = new androidx.constraintlayout.core.utils.a();
            aVar.I0 = false;
            aVar.U0 = 0;
            aVar.W0 = new HashSet();
            aVar.a1 = 0;
            aVar.k0();
            int[][] iArr = aVar.X0;
            boolean z = iArr != null && iArr.length == aVar.u0 && (zArr = aVar.V0) != null && zArr.length == aVar.J0 && zArr[0].length == aVar.L0;
            if (!z) {
                aVar.g0();
            }
            if (z) {
                for (int i = 0; i < aVar.V0.length; i++) {
                    int i2 = 0;
                    while (true) {
                        boolean[][] zArr2 = aVar.V0;
                        if (i2 < zArr2[0].length) {
                            zArr2[i][i2] = true;
                            i2++;
                        }
                    }
                }
                for (int i3 = 0; i3 < aVar.X0.length; i3++) {
                    int i4 = 0;
                    while (true) {
                        int[][] iArr2 = aVar.X0;
                        if (i4 < iArr2[0].length) {
                            iArr2[i3][i4] = -1;
                            i4++;
                        }
                    }
                }
            }
            aVar.U0 = 0;
            String str = aVar.S0;
            if (str != null && !str.trim().isEmpty() && (iArrI02 = aVar.i0(aVar.S0, false)) != null) {
                aVar.e0(iArrI02);
            }
            String str2 = aVar.R0;
            if (str2 != null && !str2.trim().isEmpty() && (iArrI0 = aVar.i0(aVar.R0, true)) != null) {
                aVar.f0(iArrI0);
            }
            this.n0 = aVar;
        }
        return this.n0;
    }
}
