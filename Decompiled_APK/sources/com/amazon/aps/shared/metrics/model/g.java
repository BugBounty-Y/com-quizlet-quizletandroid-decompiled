package com.amazon.aps.shared.metrics.model;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class g extends i {
    public final long d;

    public g(long j) {
        super(null, j, 5);
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && this.d == ((g) obj).d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d);
    }

    public final String toString() {
        return d0.q(new StringBuilder("ApsMetricsPerfAdClickEvent(timestamp="), this.d, ')');
    }
}
