package com.quizlet.features.infra.basestudy.manager;

import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final UUID a;
    public final b b;

    public c(UUID funnelId, b impressionsPayload) {
        Intrinsics.checkNotNullParameter(funnelId, "funnelId");
        Intrinsics.checkNotNullParameter(impressionsPayload, "impressionsPayload");
        this.a = funnelId;
        this.b = impressionsPayload;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "LogClickPayload(funnelId=" + this.a + ", impressionsPayload=" + this.b + ")";
    }
}
