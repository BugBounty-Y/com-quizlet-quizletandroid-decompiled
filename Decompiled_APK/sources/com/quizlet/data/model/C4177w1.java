package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.w1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4177w1 {
    public final School a;
    public final com.quizlet.generated.enums.U1 b;

    public C4177w1(School school, com.quizlet.generated.enums.U1 relationshipType) {
        Intrinsics.checkNotNullParameter(school, "school");
        Intrinsics.checkNotNullParameter(relationshipType, "relationshipType");
        this.a = school;
        this.b = relationshipType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4177w1)) {
            return false;
        }
        C4177w1 c4177w1 = (C4177w1) obj;
        return Intrinsics.b(this.a, c4177w1.a) && this.b == c4177w1.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SchoolMembership(school=" + this.a + ", relationshipType=" + this.b + ")";
    }
}
