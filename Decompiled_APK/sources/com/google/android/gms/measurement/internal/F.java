package com.google.android.gms.measurement.internal;

import android.text.TextUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class F {
    public Long A;
    public Long B;
    public long C;
    public String D;
    public int E;
    public int F;
    public long G;
    public String H;
    public byte[] I;
    public int J;
    public long K;
    public long L;
    public long M;
    public long N;
    public long O;
    public long P;
    public String Q;
    public boolean R;
    public long S;
    public long T;
    public final Y a;
    public final String b;
    public String c;
    public String d;
    public String e;
    public String f;
    public long g;
    public long h;
    public long i;
    public String j;
    public long k;
    public String l;
    public long m;
    public long n;
    public boolean o;
    public boolean p;
    public String q;
    public Boolean r;
    public long s;
    public ArrayList t;
    public String u;
    public boolean v;
    public long w;
    public long x;
    public int y;
    public boolean z;

    public F(Y y, String str) {
        com.google.android.gms.common.internal.u.h(y);
        com.google.android.gms.common.internal.u.e(str);
        this.a = y;
        this.b = str;
        X x = y.j;
        Y.k(x);
        x.S();
    }

    public final void A(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.P != j;
        this.P = j;
    }

    public final void B(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.K != j;
        this.K = j;
    }

    public final void C(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.n != j;
        this.n = j;
    }

    public final void D(int i) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.E != i;
        this.E = i;
    }

    public final void E(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.s != j;
        this.s = j;
    }

    public final void F(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.T != j;
        this.T = j;
    }

    public final void G(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.f, str);
        this.f = str;
    }

    public final void H(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        if (true == TextUtils.isEmpty(str)) {
            str = null;
        }
        this.R |= true ^ Objects.equals(this.d, str);
        this.d = str;
    }

    public final void I(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.m != j;
        this.m = j;
    }

    public final void J(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.Q, str);
        this.Q = str;
    }

    public final void K(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.G != j;
        this.G = j;
    }

    public final void L(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.i != j;
        this.i = j;
    }

    public final void M(long j) {
        com.google.android.gms.common.internal.u.b(j >= 0);
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.g != j;
        this.g = j;
    }

    public final void N(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.h != j;
        this.h = j;
    }

    public final void O(boolean z) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.o != z;
        this.o = z;
    }

    public final void P(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.e, str);
        this.e = str;
    }

    public final void Q(List list) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        if (Objects.equals(this.t, list)) {
            return;
        }
        this.R = true;
        this.t = list != null ? new ArrayList(list) : null;
    }

    public final int R() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.J;
    }

    public final long S() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.k;
    }

    public final long T() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.s;
    }

    public final Boolean U() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.r;
    }

    public final String a() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.q;
    }

    public final String b() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        String str = this.Q;
        J(null);
        return str;
    }

    public final String c() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.b;
    }

    public final String d() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.c;
    }

    public final String e() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.j;
    }

    public final String f() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.f;
    }

    public final String g() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.d;
    }

    public final String h() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.H;
    }

    public final String i() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.D;
    }

    public final void j(long j) {
        Y y = this.a;
        X x = y.j;
        Y.k(x);
        x.S();
        long j2 = this.g + j;
        String str = this.b;
        I i = y.i;
        if (j2 > 2147483647L) {
            Y.k(i);
            i.j.g("Bundle index overflow. appId", I.a0(str));
            j2 = (-1) + j;
        }
        long j3 = this.G + 1;
        if (j3 > 2147483647L) {
            Y.k(i);
            i.j.g("Delivery index overflow. appId", I.a0(str));
            j3 = 0;
        }
        this.R = true;
        this.g = j2;
        this.G = j3;
    }

    public final void k(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        if (true == TextUtils.isEmpty(str)) {
            str = null;
        }
        this.R |= true ^ Objects.equals(this.q, str);
        this.q = str;
    }

    public final void l(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.c, str);
        this.c = str;
    }

    public final void m(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.l, str);
        this.l = str;
    }

    public final void n(String str) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= !Objects.equals(this.j, str);
        this.j = str;
    }

    public final void o(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.k != j;
        this.k = j;
    }

    public final void p(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.C != j;
        this.C = j;
    }

    public final void q(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.x != j;
        this.x = j;
    }

    public final void r(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.w != j;
        this.w = j;
    }

    public final boolean s() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.R;
    }

    public final boolean t() {
        X x = this.a.j;
        Y.k(x);
        x.S();
        return this.v;
    }

    public final void u(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.S != j;
        this.S = j;
    }

    public final void v(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.N != j;
        this.N = j;
    }

    public final void w(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.O != j;
        this.O = j;
    }

    public final void x(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.M != j;
        this.M = j;
    }

    public final void y(long j) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.L != j;
        this.L = j;
    }

    public final void z(int i) {
        X x = this.a.j;
        Y.k(x);
        x.S();
        this.R |= this.F != i;
        this.F = i;
    }
}
