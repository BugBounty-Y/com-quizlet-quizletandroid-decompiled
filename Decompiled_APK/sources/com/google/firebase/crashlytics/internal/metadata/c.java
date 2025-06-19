package com.google.firebase.crashlytics.internal.metadata;

import androidx.compose.animation.d0;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final String a;
    public final long b;
    public final Map c;

    public c(long j, String sessionId, Map additionalCustomKeys) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(additionalCustomKeys, "additionalCustomKeys");
        this.a = sessionId;
        this.b = j;
        this.c = additionalCustomKeys;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "EventMetadata(sessionId=" + this.a + ", timestamp=" + this.b + ", additionalCustomKeys=" + this.c + ')';
    }
}
