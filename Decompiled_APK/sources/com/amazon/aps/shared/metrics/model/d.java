package com.amazon.aps.shared.metrics.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final e a;

    public d(e metricsEvent) {
        Intrinsics.checkNotNullParameter(metricsEvent, "metricsEvent");
        this.a = metricsEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ApsMetricsEvent(metricsEvent=" + this.a + ')';
    }
}
