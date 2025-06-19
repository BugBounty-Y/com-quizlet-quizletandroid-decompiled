package androidx.work;

import androidx.compose.animation.d0;
import java.util.HashSet;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O {
    public final UUID a;
    public final N b;
    public final HashSet c;
    public final C1437k d;
    public final C1437k e;
    public final int f;
    public final int g;
    public final C1425f h;
    public final long i;
    public final M j;
    public final long k;
    public final int l;

    public O(UUID id, N state, HashSet tags, C1437k outputData, C1437k progress, int i, int i2, C1425f constraints, long j, M m, long j2, int i3) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(tags, "tags");
        Intrinsics.checkNotNullParameter(outputData, "outputData");
        Intrinsics.checkNotNullParameter(progress, "progress");
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        this.a = id;
        this.b = state;
        this.c = tags;
        this.d = outputData;
        this.e = progress;
        this.f = i;
        this.g = i2;
        this.h = constraints;
        this.i = j;
        this.j = m;
        this.k = j2;
        this.l = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !O.class.equals(obj.getClass())) {
            return false;
        }
        O o = (O) obj;
        if (this.f == o.f && this.g == o.g && Intrinsics.b(this.a, o.a) && this.b == o.b && Intrinsics.b(this.d, o.d) && this.h.equals(o.h) && this.i == o.i && Intrinsics.b(this.j, o.j) && this.k == o.k && this.l == o.l && this.c.equals(o.c)) {
            return Intrinsics.b(this.e, o.e);
        }
        return false;
    }

    public final int hashCode() {
        int iD = d0.d((this.h.hashCode() + ((((((this.e.hashCode() + ((this.c.hashCode() + ((this.d.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31) + this.f) * 31) + this.g) * 31)) * 31, 31, this.i);
        M m = this.j;
        return Integer.hashCode(this.l) + d0.d((iD + (m != null ? m.hashCode() : 0)) * 31, 31, this.k);
    }

    public final String toString() {
        return "WorkInfo{id='" + this.a + "', state=" + this.b + ", outputData=" + this.d + ", tags=" + this.c + ", progress=" + this.e + ", runAttemptCount=" + this.f + ", generation=" + this.g + ", constraints=" + this.h + ", initialDelayMillis=" + this.i + ", periodicityInfo=" + this.j + ", nextScheduleTimeMillis=" + this.k + "}, stopReason=" + this.l;
    }
}
