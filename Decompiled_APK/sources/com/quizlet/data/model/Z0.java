package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Z0 {
    public final int a;
    public final String b;

    public Z0(int i, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Z0)) {
            return false;
        }
        Z0 z0 = (Z0) obj;
        return this.a == z0.a && Intrinsics.b(this.b, z0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTestSchool(id=" + this.a + ", name=" + this.b + ")";
    }
}
