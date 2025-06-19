package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.z0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4185z0 {
    public final Integer a;
    public final Integer b;

    public C4185z0(Integer num, Integer num2) {
        this.a = num;
        this.b = num2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4185z0)) {
            return false;
        }
        C4185z0 c4185z0 = (C4185z0) obj;
        return Intrinsics.b(this.a, c4185z0.a) && Intrinsics.b(this.b, c4185z0.b);
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        Integer num2 = this.b;
        return iHashCode + (num2 != null ? num2.hashCode() : 0);
    }

    public final String toString() {
        return "MeteringMeta(numEvents=" + this.a + ", threshold=" + this.b + ")";
    }
}
