package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import androidx.constraintlayout.core.widgets.j;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class e extends androidx.constraintlayout.core.state.g {
    public int A0;
    public int B0;
    public int C0;
    public int D0;
    public int E0;
    public int F0;
    public int G0;
    public int H0;
    public float I0;
    public float J0;
    public float K0;
    public float L0;
    public androidx.constraintlayout.core.widgets.h n0;
    public HashMap o0;
    public HashMap p0;
    public HashMap q0;
    public int r0;
    public int s0;
    public int t0;
    public int u0;
    public int v0;
    public int w0;
    public int x0;
    public int y0;
    public int z0;

    public e(k kVar, int i) {
        super(kVar, i);
        this.r0 = 0;
        this.s0 = -1;
        this.t0 = -1;
        this.u0 = -1;
        this.v0 = -1;
        this.w0 = -1;
        this.x0 = -1;
        this.y0 = 2;
        this.z0 = 2;
        this.A0 = 0;
        this.B0 = 0;
        this.C0 = 0;
        this.D0 = 0;
        this.E0 = 0;
        this.F0 = 0;
        this.G0 = -1;
        this.H0 = 0;
        this.I0 = 0.5f;
        this.J0 = 0.5f;
        this.K0 = 0.5f;
        this.L0 = 0.5f;
        if (i == 8) {
            this.H0 = 1;
        }
    }

    @Override // androidx.constraintlayout.core.state.g, androidx.constraintlayout.core.state.b, androidx.constraintlayout.core.state.h
    public final void apply() {
        s();
        a(this.n0);
        androidx.constraintlayout.core.widgets.h hVar = this.n0;
        hVar.Y0 = this.H0;
        hVar.W0 = this.r0;
        int i = this.G0;
        if (i != -1) {
            hVar.X0 = i;
        }
        int i2 = this.C0;
        if (i2 != 0) {
            hVar.z0 = i2;
        }
        int i3 = this.E0;
        if (i3 != 0) {
            hVar.v0 = i3;
        }
        int i4 = this.D0;
        if (i4 != 0) {
            hVar.A0 = i4;
        }
        int i5 = this.F0;
        if (i5 != 0) {
            hVar.w0 = i5;
        }
        int i6 = this.B0;
        if (i6 != 0) {
            hVar.S0 = i6;
        }
        int i7 = this.A0;
        if (i7 != 0) {
            hVar.T0 = i7;
        }
        float f = this.h;
        if (f != 0.5f) {
            hVar.M0 = f;
        }
        float f2 = this.K0;
        if (f2 != 0.5f) {
            hVar.O0 = f2;
        }
        float f3 = this.L0;
        if (f3 != 0.5f) {
            hVar.Q0 = f3;
        }
        float f4 = this.i;
        if (f4 != 0.5f) {
            hVar.N0 = f4;
        }
        float f5 = this.I0;
        if (f5 != 0.5f) {
            hVar.P0 = f5;
        }
        float f6 = this.J0;
        if (f6 != 0.5f) {
            hVar.R0 = f6;
        }
        int i8 = this.z0;
        if (i8 != 2) {
            hVar.U0 = i8;
        }
        int i9 = this.y0;
        if (i9 != 2) {
            hVar.V0 = i9;
        }
        int i10 = this.s0;
        if (i10 != -1) {
            hVar.H0 = i10;
        }
        int i11 = this.t0;
        if (i11 != -1) {
            hVar.J0 = i11;
        }
        int i12 = this.u0;
        if (i12 != -1) {
            hVar.L0 = i12;
        }
        int i13 = this.v0;
        if (i13 != -1) {
            hVar.G0 = i13;
        }
        int i14 = this.w0;
        if (i14 != -1) {
            hVar.I0 = i14;
        }
        int i15 = this.x0;
        if (i15 != -1) {
            hVar.K0 = i15;
        }
        r();
    }

    @Override // androidx.constraintlayout.core.state.g
    public final j s() {
        if (this.n0 == null) {
            this.n0 = new androidx.constraintlayout.core.widgets.h();
        }
        return this.n0;
    }
}
