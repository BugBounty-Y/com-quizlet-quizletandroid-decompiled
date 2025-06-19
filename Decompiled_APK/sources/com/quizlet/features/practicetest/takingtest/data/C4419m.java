package com.quizlet.features.practicetest.takingtest.data;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4419m implements y {
    public final int a;

    public C4419m(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4419m) && this.a == ((C4419m) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("GoToQuestionClicked(index="), this.a, ")");
    }
}
