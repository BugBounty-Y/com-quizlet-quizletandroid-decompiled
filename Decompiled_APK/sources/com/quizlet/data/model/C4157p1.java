package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.p1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4157p1 extends AbstractC4165s1 {
    public final Object a;

    public C4157p1(List recommendedStudySets) {
        Intrinsics.checkNotNullParameter(recommendedStudySets, "recommendedStudySets");
        this.a = recommendedStudySets;
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
        return (obj instanceof C4157p1) && Intrinsics.b(this.a, ((C4157p1) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("RecommendedAgeLocationSets(recommendedStudySets="), this.a, ")");
    }
}
