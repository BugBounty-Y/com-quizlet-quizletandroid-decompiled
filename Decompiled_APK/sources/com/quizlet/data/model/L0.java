package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L0 {
    public final int a;
    public final String b;

    public L0(int i, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L0)) {
            return false;
        }
        L0 l0 = (L0) obj;
        return this.a == l0.a && Intrinsics.b(this.b, l0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTestCourse(id=" + this.a + ", name=" + this.b + ")";
    }
}
