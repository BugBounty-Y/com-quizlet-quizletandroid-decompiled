package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class N {
    public final Object a;
    public final J0 b;

    public N(Object obj, J0 j0) {
        this.a = obj;
        this.b = j0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof N)) {
            return false;
        }
        N n = (N) obj;
        return Intrinsics.b(this.a, n.a) && Intrinsics.b(this.b, n.b);
    }

    public final int hashCode() {
        Object obj = this.a;
        int iHashCode = (obj == null ? 0 : obj.hashCode()) * 31;
        J0 j0 = this.b;
        return iHashCode + (j0 != null ? j0.hashCode() : 0);
    }

    public final String toString() {
        return "DataWithPaging(data=" + this.a + ", pagingKey=" + this.b + ")";
    }
}
