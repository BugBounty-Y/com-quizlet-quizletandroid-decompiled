package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4413g implements InterfaceC4415i {
    public final int a;
    public final String b;

    public C4413g(int i, String answer) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = i;
        this.b = answer;
    }

    @Override // com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i
    public final boolean a() {
        return this.b.length() > 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4413g)) {
            return false;
        }
        C4413g c4413g = (C4413g) obj;
        return this.a == c4413g.a && Intrinsics.b(this.b, c4413g.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "MultipleChoice(index=" + this.a + ", answer=" + this.b + ")";
    }
}
