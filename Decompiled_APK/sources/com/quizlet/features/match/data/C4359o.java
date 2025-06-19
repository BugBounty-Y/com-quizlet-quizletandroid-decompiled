package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4359o {
    public final com.quizlet.qutils.string.f a;
    public final com.quizlet.qutils.string.f b;
    public final com.quizlet.qutils.string.f c;
    public final M d;
    public final W e;

    public C4359o(com.quizlet.qutils.string.f currentScoreRes, com.quizlet.qutils.string.f highScoreRes, com.quizlet.qutils.string.f personalRecordRes, M buttonState, W shareSetData) {
        Intrinsics.checkNotNullParameter(currentScoreRes, "currentScoreRes");
        Intrinsics.checkNotNullParameter(highScoreRes, "highScoreRes");
        Intrinsics.checkNotNullParameter(personalRecordRes, "personalRecordRes");
        Intrinsics.checkNotNullParameter(buttonState, "buttonState");
        Intrinsics.checkNotNullParameter(shareSetData, "shareSetData");
        this.a = currentScoreRes;
        this.b = highScoreRes;
        this.c = personalRecordRes;
        this.d = buttonState;
        this.e = shareSetData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4359o)) {
            return false;
        }
        C4359o c4359o = (C4359o) obj;
        return this.a.equals(c4359o.a) && this.b.equals(c4359o.b) && this.c.equals(c4359o.c) && Intrinsics.b(this.d, c4359o.d) && Intrinsics.b(this.e, c4359o.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "MatchEndViewState(currentScoreRes=" + this.a + ", highScoreRes=" + this.b + ", personalRecordRes=" + this.c + ", buttonState=" + this.d + ", shareSetData=" + this.e + ")";
    }
}
