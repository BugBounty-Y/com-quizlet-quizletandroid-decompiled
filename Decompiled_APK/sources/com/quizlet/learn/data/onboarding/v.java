package com.quizlet.learn.data.onboarding;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v {
    public final kotlinx.collections.immutable.e a;
    public final t b;

    public v(kotlinx.collections.immutable.e knowledgeItems, t defaultKnowledge) {
        Intrinsics.checkNotNullParameter(knowledgeItems, "knowledgeItems");
        Intrinsics.checkNotNullParameter(defaultKnowledge, "defaultKnowledge");
        this.a = knowledgeItems;
        this.b = defaultKnowledge;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v)) {
            return false;
        }
        v vVar = (v) obj;
        return Intrinsics.b(this.a, vVar.a) && Intrinsics.b(this.b, vVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        this.b.getClass();
        return 1219805902 + iHashCode;
    }

    public final String toString() {
        return "OnboardingKnowledgeState(knowledgeItems=" + this.a + ", defaultKnowledge=" + this.b + ")";
    }
}
