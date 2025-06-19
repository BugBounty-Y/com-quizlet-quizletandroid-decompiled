package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class P1 implements Q1 {
    public final A0 a;
    public final A0 b;
    public final InterfaceC4156p0 c;
    public final InterfaceC4156p0 d;
    public final com.quizlet.featuregate.contracts.enums.a e;

    public P1(A0 learnState, A0 testState, InterfaceC4156p0 blocksState, InterfaceC4156p0 blastState, com.quizlet.featuregate.contracts.enums.a alternateStudyModeNamesType) {
        Intrinsics.checkNotNullParameter(learnState, "learnState");
        Intrinsics.checkNotNullParameter(testState, "testState");
        Intrinsics.checkNotNullParameter(blocksState, "blocksState");
        Intrinsics.checkNotNullParameter(blastState, "blastState");
        Intrinsics.checkNotNullParameter(alternateStudyModeNamesType, "alternateStudyModeNamesType");
        this.a = learnState;
        this.b = testState;
        this.c = blocksState;
        this.d = blastState;
        this.e = alternateStudyModeNamesType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof P1)) {
            return false;
        }
        P1 p1 = (P1) obj;
        return this.a == p1.a && this.b == p1.b && Intrinsics.b(this.c, p1.c) && Intrinsics.b(this.d, p1.d) && this.e == p1.e;
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Visible(learnState=" + this.a + ", testState=" + this.b + ", blocksState=" + this.c + ", blastState=" + this.d + ", alternateStudyModeNamesType=" + this.e + ")";
    }
}
