package com.amazon.aps.shared.metrics.model;

/* loaded from: classes.dex */
public final class j extends i {
    @Override // com.amazon.aps.shared.metrics.model.i
    public final m a() {
        return m.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        ((j) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return m.a.hashCode();
    }

    public final String toString() {
        return "ApsMetricsPerfImpressionFiredEvent(result=" + m.a + ')';
    }
}
