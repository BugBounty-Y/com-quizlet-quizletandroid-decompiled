package com.quizlet.features.settings.data.states;

/* loaded from: classes3.dex */
public final class u implements x {
    public final com.quizlet.features.settings.data.models.b a;

    public u(com.quizlet.features.settings.data.models.b bVar) {
        this.a = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && this.a == ((u) obj).a;
    }

    public final int hashCode() {
        com.quizlet.features.settings.data.models.b bVar = this.a;
        if (bVar == null) {
            return 0;
        }
        return bVar.hashCode();
    }

    public final String toString() {
        return "Idle(requestType=" + this.a + ")";
    }
}
