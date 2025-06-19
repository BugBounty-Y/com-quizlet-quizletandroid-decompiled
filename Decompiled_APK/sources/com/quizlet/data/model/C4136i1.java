package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.i1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4136i1 {
    public final C4133h1 a;
    public final School b;

    public C4136i1(C4133h1 qClass, School school) {
        Intrinsics.checkNotNullParameter(qClass, "qClass");
        this.a = qClass;
        this.b = school;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4136i1)) {
            return false;
        }
        C4136i1 c4136i1 = (C4136i1) obj;
        return Intrinsics.b(this.a, c4136i1.a) && Intrinsics.b(this.b, c4136i1.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        School school = this.b;
        return iHashCode + (school == null ? 0 : school.hashCode());
    }

    public final String toString() {
        return "QClassWithSchool(qClass=" + this.a + ", school=" + this.b + ")";
    }
}
