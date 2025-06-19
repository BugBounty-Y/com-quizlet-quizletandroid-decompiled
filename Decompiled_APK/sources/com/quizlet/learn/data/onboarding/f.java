package com.quizlet.learn.data.onboarding;

/* loaded from: classes3.dex */
public final class f extends i {
    public final com.quizlet.studiablemodels.assistantMode.a a;
    public final assistantMode.enums.y b;

    public f(com.quizlet.studiablemodels.assistantMode.a aVar, assistantMode.enums.y yVar) {
        this.a = aVar;
        this.b = yVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && this.b == fVar.b;
    }

    public final int hashCode() {
        com.quizlet.studiablemodels.assistantMode.a aVar = this.a;
        int iHashCode = (aVar == null ? 0 : aVar.hashCode()) * 31;
        assistantMode.enums.y yVar = this.b;
        return iHashCode + (yVar != null ? yVar.hashCode() : 0);
    }

    public final String toString() {
        return "OptionSelect(goalOption=" + this.a + ", knowledgeLevel=" + this.b + ")";
    }
}
