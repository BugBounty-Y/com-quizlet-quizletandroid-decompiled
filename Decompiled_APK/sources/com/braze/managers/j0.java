package com.braze.managers;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j0 {
    public final String a;
    public final long b;

    public j0(String id, long j) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j0)) {
            return false;
        }
        j0 j0Var = (j0) obj;
        return Intrinsics.b(this.a, j0Var.a) && this.b == j0Var.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CampaignData(id=");
        sb.append(this.a);
        sb.append(", timestamp=");
        return androidx.compose.animation.d0.q(sb, this.b, ')');
    }
}
