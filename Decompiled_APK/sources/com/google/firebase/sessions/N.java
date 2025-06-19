package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class N {
    public final String a;
    public final String b;
    public final int c;
    public final long d;

    public N(int i, long j, String sessionId, String firstSessionId) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(firstSessionId, "firstSessionId");
        this.a = sessionId;
        this.b = firstSessionId;
        this.c = i;
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof N)) {
            return false;
        }
        N n = (N) obj;
        return Intrinsics.b(this.a, n.a) && Intrinsics.b(this.b, n.b) && this.c == n.c && this.d == n.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SessionDetails(sessionId=");
        sb.append(this.a);
        sb.append(", firstSessionId=");
        sb.append(this.b);
        sb.append(", sessionIndex=");
        sb.append(this.c);
        sb.append(", sessionStartTimestampUs=");
        return androidx.compose.animation.d0.q(sb, this.d, ')');
    }
}
