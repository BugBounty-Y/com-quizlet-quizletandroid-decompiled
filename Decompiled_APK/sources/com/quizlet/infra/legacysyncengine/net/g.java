package com.quizlet.infra.legacysyncengine.net;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public List a;
    public final AtomicInteger b;

    public g(List list, int i) {
        AtomicInteger trackCount = new AtomicInteger(i);
        Intrinsics.checkNotNullParameter(trackCount, "trackCount");
        this.a = list;
        this.b = trackCount;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        List list = this.a;
        return this.b.hashCode() + ((list == null ? 0 : list.hashCode()) * 31);
    }

    public final String toString() {
        return "TrackedResponses(responses=" + this.a + ", trackCount=" + this.b + ")";
    }
}
