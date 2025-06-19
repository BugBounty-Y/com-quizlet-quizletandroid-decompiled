package com.amazon.aps.shared.metrics.model;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class l extends i {
    public final long d;

    public l(long j) {
        super(null, j, 5);
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && this.d == ((l) obj).d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d);
    }

    public final String toString() {
        return d0.q(new StringBuilder("ApsMetricsPerfVideoCompletedEvent(timestamp="), this.d, ')');
    }
}
