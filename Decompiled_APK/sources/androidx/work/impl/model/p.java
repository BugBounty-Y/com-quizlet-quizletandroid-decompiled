package androidx.work.impl.model;

import androidx.compose.animation.d0;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.M;
import androidx.work.N;
import androidx.work.O;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p {
    public final String a;
    public final N b;
    public final C1437k c;
    public final long d;
    public final long e;
    public final long f;
    public final C1425f g;
    public final int h;
    public final EnumC1420a i;
    public final long j;
    public final long k;
    public final int l;
    public final int m;
    public final long n;
    public final int o;
    public final ArrayList p;
    public final ArrayList q;

    public p(String id, N state, C1437k output, long j, long j2, long j3, C1425f constraints, int i, EnumC1420a backoffPolicy, long j4, long j5, int i2, int i3, long j6, int i4, ArrayList tags, ArrayList progress) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        Intrinsics.checkNotNullParameter(backoffPolicy, "backoffPolicy");
        Intrinsics.checkNotNullParameter(tags, "tags");
        Intrinsics.checkNotNullParameter(progress, "progress");
        this.a = id;
        this.b = state;
        this.c = output;
        this.d = j;
        this.e = j2;
        this.f = j3;
        this.g = constraints;
        this.h = i;
        this.i = backoffPolicy;
        this.j = j4;
        this.k = j5;
        this.l = i2;
        this.m = i3;
        this.n = j6;
        this.o = i4;
        this.p = tags;
        this.q = progress;
    }

    public final O a() {
        M m;
        int i;
        long j;
        long jC;
        boolean z;
        ArrayList arrayList = this.q;
        C1437k c1437k = !arrayList.isEmpty() ? (C1437k) arrayList.get(0) : C1437k.b;
        UUID uuidFromString = UUID.fromString(this.a);
        Intrinsics.checkNotNullExpressionValue(uuidFromString, "fromString(id)");
        HashSet hashSet = new HashSet(this.p);
        long j2 = this.e;
        M m2 = j2 != 0 ? new M(j2, this.f) : null;
        N n = N.a;
        N n2 = this.b;
        int i2 = this.h;
        long j3 = this.d;
        if (n2 == n) {
            String str = q.y;
            boolean z2 = true;
            if (n2 != n || i2 <= 0) {
                z = true;
                z2 = false;
            } else {
                z = true;
            }
            m = m2;
            j = j3;
            jC = AbstractC3418z2.c(z2, i2, this.i, this.j, this.k, this.l, j2 != 0 ? z : false, j, this.f, j2, this.n);
            i = i2;
        } else {
            m = m2;
            i = i2;
            j = j3;
            jC = Long.MAX_VALUE;
        }
        return new O(uuidFromString, n2, hashSet, this.c, c1437k, i, this.m, this.g, j, m, jC, this.o);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && this.b == pVar.b && Intrinsics.b(this.c, pVar.c) && this.d == pVar.d && this.e == pVar.e && this.f == pVar.f && this.g.equals(pVar.g) && this.h == pVar.h && this.i == pVar.i && this.j == pVar.j && this.k == pVar.k && this.l == pVar.l && this.m == pVar.m && this.n == pVar.n && this.o == pVar.o && Intrinsics.b(this.p, pVar.p) && Intrinsics.b(this.q, pVar.q);
    }

    public final int hashCode() {
        return this.q.hashCode() + d0.h(this.p, d0.b(this.o, d0.d(d0.b(this.m, d0.b(this.l, d0.d(d0.d((this.i.hashCode() + d0.b(this.h, (this.g.hashCode() + d0.d(d0.d(d0.d((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31, 31, this.d), 31, this.e), 31, this.f)) * 31, 31)) * 31, 31, this.j), 31, this.k), 31), 31), 31, this.n), 31), 31);
    }

    public final String toString() {
        return "WorkInfoPojo(id=" + this.a + ", state=" + this.b + ", output=" + this.c + ", initialDelay=" + this.d + ", intervalDuration=" + this.e + ", flexDuration=" + this.f + ", constraints=" + this.g + ", runAttemptCount=" + this.h + ", backoffPolicy=" + this.i + ", backoffDelayDuration=" + this.j + ", lastEnqueueTime=" + this.k + ", periodCount=" + this.l + ", generation=" + this.m + ", nextScheduleTimeOverride=" + this.n + ", stopReason=" + this.o + ", tags=" + this.p + ", progress=" + this.q + ')';
    }
}
