package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.MissingResourceException;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.aG, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1832aG {
    public static final /* synthetic */ int L = 0;
    public final C2135hD A;
    public final int B;
    public final int C;
    public final int D;
    public final int E;
    public final int F;
    public final int G;
    public final int H;
    public final int I;
    public final int J;
    public int K;
    public final String a;
    public final String b;
    public final AbstractC2330lu c;
    public final String d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final int i;
    public final String j;
    public final K4 k;
    public final String l;
    public final String m;
    public final int n;
    public final int o;
    public final List p;
    public final zzs q;
    public final long r;
    public final boolean s;
    public final int t;
    public final int u;
    public final float v;
    public final int w;
    public final float x;
    public final byte[] y;
    public final int z;

    static {
        new C1832aG(new EF());
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
        Integer.toString(7, 36);
        Integer.toString(8, 36);
        Integer.toString(9, 36);
        Integer.toString(10, 36);
        Integer.toString(11, 36);
        Integer.toString(12, 36);
        Integer.toString(13, 36);
        Integer.toString(14, 36);
        Integer.toString(15, 36);
        Integer.toString(16, 36);
        Integer.toString(17, 36);
        Integer.toString(18, 36);
        Integer.toString(19, 36);
        Integer.toString(20, 36);
        Integer.toString(21, 36);
        Integer.toString(22, 36);
        Integer.toString(23, 36);
        Integer.toString(24, 36);
        Integer.toString(25, 36);
        Integer.toString(26, 36);
        Integer.toString(27, 36);
        Integer.toString(28, 36);
        Integer.toString(29, 36);
        Integer.toString(30, 36);
        Integer.toString(31, 36);
        Integer.toString(32, 36);
        Integer.toString(33, 36);
        Integer.toString(34, 36);
    }

    public C1832aG(EF ef) throws MissingResourceException {
        boolean z;
        String str;
        this.a = ef.a;
        String strA = Yo.a(ef.d);
        this.d = strA;
        if (ef.c.isEmpty() && ef.b != null) {
            this.c = AbstractC2330lu.s(new C2379n(strA, ef.b));
            this.b = ef.b;
        } else if (!ef.c.isEmpty() && ef.b == null) {
            AbstractC2330lu abstractC2330lu = ef.c;
            this.c = abstractC2330lu;
            Iterator it2 = abstractC2330lu.iterator();
            while (true) {
                C2244ju c2244ju = (C2244ju) it2;
                if (!c2244ju.hasNext()) {
                    str = ((C2379n) abstractC2330lu.get(0)).b;
                    break;
                }
                C2379n c2379n = (C2379n) c2244ju.next();
                if (TextUtils.equals(c2379n.a, strA)) {
                    str = c2379n.b;
                    break;
                }
            }
            this.b = str;
        } else if (ef.c.isEmpty() && ef.b == null) {
            z = true;
            AbstractC1795We.L(z);
            this.c = ef.c;
            this.b = ef.b;
        } else {
            for (int i = 0; i < ef.c.size(); i++) {
                if (((C2379n) ef.c.get(i)).b.equals(ef.b)) {
                    z = true;
                    break;
                }
            }
            z = false;
            AbstractC1795We.L(z);
            this.c = ef.c;
            this.b = ef.b;
        }
        this.e = ef.e;
        this.f = ef.f;
        int i2 = ef.g;
        this.g = i2;
        int i3 = ef.h;
        this.h = i3;
        this.i = i3 != -1 ? i3 : i2;
        this.j = ef.i;
        this.k = ef.j;
        this.l = ef.k;
        this.m = ef.l;
        this.n = ef.m;
        this.o = ef.n;
        List list = ef.o;
        this.p = list == null ? Collections.EMPTY_LIST : list;
        zzs zzsVar = ef.p;
        this.q = zzsVar;
        this.r = ef.q;
        this.s = ef.r;
        this.t = ef.s;
        this.u = ef.t;
        this.v = ef.u;
        int i4 = ef.v;
        this.w = i4 == -1 ? 0 : i4;
        float f = ef.w;
        this.x = f == -1.0f ? 1.0f : f;
        this.y = ef.x;
        this.z = ef.y;
        this.A = ef.z;
        this.B = ef.A;
        this.C = ef.B;
        this.D = ef.C;
        this.E = ef.D;
        int i5 = ef.E;
        this.F = i5 == -1 ? 0 : i5;
        int i6 = ef.F;
        this.G = i6 != -1 ? i6 : 0;
        this.H = ef.G;
        this.I = ef.H;
        int i7 = ef.I;
        if (i7 != 0 || zzsVar == null) {
            this.J = i7;
        } else {
            this.J = 1;
        }
    }

    public final EF a() {
        return new EF(this);
    }

    public final boolean b(C1832aG c1832aG) {
        List list = this.p;
        int size = list.size();
        List list2 = c1832aG.p;
        if (size != list2.size()) {
            return false;
        }
        for (int i = 0; i < list.size(); i++) {
            if (!Arrays.equals((byte[]) list.get(i), (byte[]) list2.get(i))) {
                return false;
            }
        }
        return true;
    }

    public final boolean equals(Object obj) {
        int i;
        if (this == obj) {
            return true;
        }
        if (obj == null || C1832aG.class != obj.getClass()) {
            return false;
        }
        C1832aG c1832aG = (C1832aG) obj;
        int i2 = this.K;
        return (i2 == 0 || (i = c1832aG.K) == 0 || i2 == i) && this.e == c1832aG.e && this.f == c1832aG.f && this.g == c1832aG.g && this.h == c1832aG.h && this.n == c1832aG.n && this.r == c1832aG.r && this.t == c1832aG.t && this.u == c1832aG.u && this.w == c1832aG.w && this.z == c1832aG.z && this.B == c1832aG.B && this.C == c1832aG.C && this.D == c1832aG.D && this.E == c1832aG.E && this.F == c1832aG.F && this.G == c1832aG.G && this.H == c1832aG.H && this.J == c1832aG.J && Float.compare(this.v, c1832aG.v) == 0 && Float.compare(this.x, c1832aG.x) == 0 && Objects.equals(this.a, c1832aG.a) && Objects.equals(this.b, c1832aG.b) && this.c.equals(c1832aG.c) && Objects.equals(this.j, c1832aG.j) && Objects.equals(this.l, c1832aG.l) && Objects.equals(this.m, c1832aG.m) && Objects.equals(this.d, c1832aG.d) && Arrays.equals(this.y, c1832aG.y) && Objects.equals(this.k, c1832aG.k) && Objects.equals(this.A, c1832aG.A) && Objects.equals(this.q, c1832aG.q) && b(c1832aG);
    }

    public final int hashCode() {
        int i = this.K;
        if (i != 0) {
            return i;
        }
        String str = this.a;
        int iHashCode = str == null ? 0 : str.hashCode();
        String str2 = this.b;
        int iHashCode2 = this.c.hashCode() + ((((iHashCode + 527) * 31) + (str2 == null ? 0 : str2.hashCode())) * 31);
        String str3 = this.d;
        int iHashCode3 = ((((((((((iHashCode2 * 31) + (str3 == null ? 0 : str3.hashCode())) * 31) + this.e) * 31) + this.f) * 961) + this.g) * 31) + this.h) * 31;
        String str4 = this.j;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        K4 k4 = this.k;
        int iHashCode5 = iHashCode4 + (k4 == null ? 0 : k4.hashCode());
        String str5 = this.l;
        int iHashCode6 = ((iHashCode5 * 961) + (str5 == null ? 0 : str5.hashCode())) * 31;
        int iFloatToIntBits = ((((((((((((((((((((((Float.floatToIntBits(this.x) + ((((Float.floatToIntBits(this.v) + ((((((((((iHashCode6 + (this.m != null ? r1.hashCode() : 0)) * 31) + this.n) * 31) + ((int) this.r)) * 31) + this.t) * 31) + this.u) * 31)) * 31) + this.w) * 31)) * 31) + this.z) * 31) + this.B) * 31) + this.C) * 31) + this.D) * 31) + this.E) * 31) + this.F) * 31) + this.G) * 31) + this.H) * 31) - 1) * 31) - 1) * 31) + this.J;
        this.K = iFloatToIntBits;
        return iFloatToIntBits;
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.A);
        StringBuilder sb = new StringBuilder("Format(");
        sb.append(this.a);
        sb.append(", ");
        sb.append(this.b);
        sb.append(", ");
        sb.append(this.l);
        sb.append(", ");
        sb.append(this.m);
        sb.append(", ");
        sb.append(this.j);
        sb.append(", ");
        sb.append(this.i);
        sb.append(", ");
        sb.append(this.d);
        sb.append(", [");
        sb.append(this.t);
        sb.append(", ");
        sb.append(this.u);
        sb.append(", ");
        sb.append(this.v);
        sb.append(", ");
        sb.append(strValueOf);
        sb.append("], [");
        sb.append(this.C);
        sb.append(", ");
        return android.support.v4.media.session.a.r(sb, this.D, "])");
    }
}
