package com.snowplowanalytics.snowplow.util;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Serializable {
    public final long a;
    public final TimeUnit b;

    public c(long j, TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        this.a = j;
        this.b = unit;
    }

    public final long a(TimeUnit toUnit) {
        Intrinsics.checkNotNullParameter(toUnit, "toUnit");
        return toUnit.convert(this.a, this.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && c.class.equals(obj.getClass())) {
            c cVar = obj instanceof c ? (c) obj : null;
            TimeUnit timeUnit = TimeUnit.MILLISECONDS;
            long jA = a(timeUnit);
            Long lValueOf = cVar != null ? Long.valueOf(cVar.a(timeUnit)) : null;
            if (lValueOf != null && jA == lValueOf.longValue()) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        long j = this.a;
        return this.b.hashCode() + (((int) (j ^ (j >>> 32))) * 31);
    }

    public final String toString() {
        return "TimeMeasure{value=" + this.a + ", unit=" + this.b + '}';
    }
}
