package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.q1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4160q1 extends AbstractC4165s1 {
    public final Object a;
    public final User b;
    public final StudySet c;

    public C4160q1(List recommendedStudySets, User user, StudySet studySet) {
        Intrinsics.checkNotNullParameter(recommendedStudySets, "recommendedStudySets");
        this.a = recommendedStudySets;
        this.b = user;
        this.c = studySet;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.List] */
    @Override // com.quizlet.data.model.AbstractC4165s1
    public final List a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4160q1)) {
            return false;
        }
        C4160q1 c4160q1 = (C4160q1) obj;
        return Intrinsics.b(this.a, c4160q1.a) && Intrinsics.b(this.b, c4160q1.b) && Intrinsics.b(this.c, c4160q1.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        int iHashCode2 = (iHashCode + (user == null ? 0 : user.hashCode())) * 31;
        StudySet studySet = this.c;
        return iHashCode2 + (studySet != null ? studySet.hashCode() : 0);
    }

    public final String toString() {
        return "RecommendedBehaviorSets(recommendedStudySets=" + this.a + ", userSource=" + this.b + ", setSource=" + this.c + ")";
    }
}
