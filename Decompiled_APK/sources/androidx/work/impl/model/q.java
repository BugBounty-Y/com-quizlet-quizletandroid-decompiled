package androidx.work.impl.model;

import androidx.camera.camera2.internal.s0;
import androidx.compose.animation.d0;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.N;
import androidx.work.OverwritingInputMerger;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q {
    public static final String y;
    public static final s0 z;
    public final String a;
    public N b;
    public final String c;
    public final String d;
    public C1437k e;
    public final C1437k f;
    public long g;
    public long h;
    public long i;
    public C1425f j;
    public final int k;
    public EnumC1420a l;
    public long m;
    public long n;
    public final long o;
    public final long p;
    public boolean q;
    public final J r;
    public final int s;
    public final int t;
    public final long u;
    public final int v;
    public final int w;
    public String x;

    static {
        String strE = z.e("WorkSpec");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"WorkSpec\")");
        y = strE;
        z = new s0(19);
    }

    public q(String id, N state, String workerClassName, String inputMergerClassName, C1437k input, C1437k output, long j, long j2, long j3, C1425f constraints, int i, EnumC1420a backoffPolicy, long j4, long j5, long j6, long j7, boolean z2, J outOfQuotaPolicy, int i2, int i3, long j8, int i4, int i5, String str) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(workerClassName, "workerClassName");
        Intrinsics.checkNotNullParameter(inputMergerClassName, "inputMergerClassName");
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        Intrinsics.checkNotNullParameter(backoffPolicy, "backoffPolicy");
        Intrinsics.checkNotNullParameter(outOfQuotaPolicy, "outOfQuotaPolicy");
        this.a = id;
        this.b = state;
        this.c = workerClassName;
        this.d = inputMergerClassName;
        this.e = input;
        this.f = output;
        this.g = j;
        this.h = j2;
        this.i = j3;
        this.j = constraints;
        this.k = i;
        this.l = backoffPolicy;
        this.m = j4;
        this.n = j5;
        this.o = j6;
        this.p = j7;
        this.q = z2;
        this.r = outOfQuotaPolicy;
        this.s = i2;
        this.t = i3;
        this.u = j8;
        this.v = i4;
        this.w = i5;
        this.x = str;
    }

    public final long a() {
        return AbstractC3418z2.c(this.b == N.a && this.k > 0, this.k, this.l, this.m, this.n, this.s, c(), this.g, this.i, this.h, this.u);
    }

    public final boolean b() {
        return !Intrinsics.b(C1425f.j, this.j);
    }

    public final boolean c() {
        return this.h != 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return Intrinsics.b(this.a, qVar.a) && this.b == qVar.b && Intrinsics.b(this.c, qVar.c) && Intrinsics.b(this.d, qVar.d) && Intrinsics.b(this.e, qVar.e) && Intrinsics.b(this.f, qVar.f) && this.g == qVar.g && this.h == qVar.h && this.i == qVar.i && Intrinsics.b(this.j, qVar.j) && this.k == qVar.k && this.l == qVar.l && this.m == qVar.m && this.n == qVar.n && this.o == qVar.o && this.p == qVar.p && this.q == qVar.q && this.r == qVar.r && this.s == qVar.s && this.t == qVar.t && this.u == qVar.u && this.v == qVar.v && this.w == qVar.w && Intrinsics.b(this.x, qVar.x);
    }

    public final int hashCode() {
        int iB = d0.b(this.w, d0.b(this.v, d0.d(d0.b(this.t, d0.b(this.s, (this.r.hashCode() + d0.g(d0.d(d0.d(d0.d(d0.d((this.l.hashCode() + d0.b(this.k, (this.j.hashCode() + d0.d(d0.d(d0.d((this.f.hashCode() + ((this.e.hashCode() + d0.e(d0.e((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), 31, this.d)) * 31)) * 31, 31, this.g), 31, this.h), 31, this.i)) * 31, 31)) * 31, 31, this.m), 31, this.n), 31, this.o), 31, this.p), 31, this.q)) * 31, 31), 31), 31, this.u), 31), 31);
        String str = this.x;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        return d0.r(new StringBuilder("{WorkSpec: "), this.a, '}');
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ q(String str, N n, String str2, String str3, C1437k c1437k, C1437k c1437k2, long j, long j2, long j3, C1425f c1425f, int i, EnumC1420a enumC1420a, long j4, long j5, long j6, long j7, boolean z2, J j8, int i2, long j9, int i3, int i4, String str4, int i5) {
        String str5;
        N n2 = (i5 & 2) != 0 ? N.a : n;
        if ((i5 & 8) != 0) {
            String name = OverwritingInputMerger.class.getName();
            Intrinsics.checkNotNullExpressionValue(name, "OverwritingInputMerger::class.java.name");
            str5 = name;
        } else {
            str5 = str3;
        }
        this(str, n2, str2, str5, (i5 & 16) != 0 ? C1437k.b : c1437k, (i5 & 32) != 0 ? C1437k.b : c1437k2, (i5 & 64) != 0 ? 0L : j, (i5 & 128) != 0 ? 0L : j2, (i5 & 256) != 0 ? 0L : j3, (i5 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? C1425f.j : c1425f, (i5 & 1024) != 0 ? 0 : i, (i5 & 2048) != 0 ? EnumC1420a.a : enumC1420a, (i5 & 4096) != 0 ? 30000L : j4, (i5 & 8192) != 0 ? -1L : j5, (i5 & 16384) == 0 ? j6 : 0L, (32768 & i5) != 0 ? -1L : j7, (65536 & i5) != 0 ? false : z2, (131072 & i5) != 0 ? J.a : j8, (262144 & i5) != 0 ? 0 : i2, 0, (1048576 & i5) != 0 ? Long.MAX_VALUE : j9, (2097152 & i5) != 0 ? 0 : i3, (4194304 & i5) != 0 ? -256 : i4, (i5 & 8388608) != 0 ? null : str4);
    }
}
