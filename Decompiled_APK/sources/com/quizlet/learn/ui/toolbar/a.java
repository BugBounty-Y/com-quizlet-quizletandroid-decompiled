package com.quizlet.learn.ui.toolbar;

import com.quizlet.studiablemodels.StudiableRoundProgress;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final StudiableRoundProgress a;

    public a(StudiableRoundProgress studiableRoundProgress) {
        this.a = studiableRoundProgress;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        StudiableRoundProgress studiableRoundProgress = this.a;
        if (studiableRoundProgress == null) {
            return 0;
        }
        return studiableRoundProgress.hashCode();
    }

    public final String toString() {
        return "AssistantLearnToolbarState(roundProgress=" + this.a + ")";
    }
}
