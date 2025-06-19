package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class X1 {
    public final int a;
    public final String b;

    public X1(int i, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = i;
        this.b = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof X1)) {
            return false;
        }
        X1 x1 = (X1) obj;
        return this.a == x1.a && Intrinsics.b(this.b, x1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudySetLineage(level=" + this.a + ", name=" + this.b + ")";
    }
}
