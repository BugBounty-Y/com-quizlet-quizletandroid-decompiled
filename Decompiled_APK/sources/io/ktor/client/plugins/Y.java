package io.ktor.client.plugins;

import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class Y {
    public Long a;
    public Long b;
    public Long c;

    static {
        kotlin.jvm.internal.U uC;
        C4950i c4950iA = kotlin.jvm.internal.K.a(Y.class);
        try {
            uC = kotlin.jvm.internal.K.c(Y.class);
        } catch (Throwable unused) {
            uC = null;
        }
        io.ktor.util.reflect.a type = new io.ktor.util.reflect.a(c4950iA, uC);
        Intrinsics.checkNotNullParameter("TimeoutConfiguration", "name");
        Intrinsics.checkNotNullParameter(type, "type");
        if (StringsKt.O("TimeoutConfiguration")) {
            throw new IllegalArgumentException("Name can't be blank");
        }
    }

    public Y() {
        this.a = 0L;
        this.b = 0L;
        this.c = 0L;
        this.a = null;
        this.b = null;
        this.c = null;
    }

    public static void a(Long l) {
        if (l != null && l.longValue() <= 0) {
            throw new IllegalArgumentException("Only positive timeout values are allowed, for infinite timeout use HttpTimeout.INFINITE_TIMEOUT_MS");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || Y.class != obj.getClass()) {
            return false;
        }
        Y y = (Y) obj;
        return Intrinsics.b(this.a, y.a) && Intrinsics.b(this.b, y.b) && Intrinsics.b(this.c, y.c);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l != null ? l.hashCode() : 0) * 31;
        Long l2 = this.b;
        int iHashCode2 = (iHashCode + (l2 != null ? l2.hashCode() : 0)) * 31;
        Long l3 = this.c;
        return iHashCode2 + (l3 != null ? l3.hashCode() : 0);
    }
}
