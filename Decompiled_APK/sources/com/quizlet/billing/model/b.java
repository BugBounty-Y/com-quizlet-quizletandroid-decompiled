package com.quizlet.billing.model;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final long a;
    public final String b;
    public final int c;
    public final int d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;

    public /* synthetic */ b(int i, int i2, int i3, long j, String str) {
        this((i3 & 1) != 0 ? -1L : j, (i3 & 2) != 0 ? null : str, (i3 & 4) != 0 ? 0 : i, (i3 & 8) != 0 ? 0 : i2, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && this.c == bVar.c && this.d == bVar.d && this.e == bVar.e;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return Boolean.hashCode(this.e) + d0.b(this.d, d0.b(this.c, (iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BillingUser(id=");
        sb.append(this.a);
        sb.append(", obfuscatedUserId=");
        sb.append(this.b);
        sb.append(", selfIdentifiedUserType=");
        sb.append(this.c);
        sb.append(", upgradeType=");
        sb.append(this.d);
        sb.append(", isEligibleForFreeTrial=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }

    public b(long j, String str, int i, int i2, boolean z) {
        this.a = j;
        this.b = str;
        this.c = i;
        this.d = i2;
        this.e = z;
        boolean z2 = false;
        boolean z3 = i2 == 1 || i2 == 3;
        boolean z4 = i2 == 2;
        this.f = i == 1;
        boolean z5 = j > 0;
        this.g = z5;
        if (z5 && !z3 && !z4) {
            z2 = true;
        }
        this.h = z2;
    }
}
