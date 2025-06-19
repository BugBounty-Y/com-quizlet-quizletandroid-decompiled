package com.quizlet.learn.ui.toolbar;

import com.quizlet.studiablemodels.StudiableRoundProgress;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends j {
    public final StudiableRoundProgress b;

    public i(StudiableRoundProgress studiableRoundProgress) {
        super(true);
        this.b = studiableRoundProgress;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.b, ((i) obj).b);
    }

    public final int hashCode() {
        StudiableRoundProgress studiableRoundProgress = this.b;
        if (studiableRoundProgress == null) {
            return 0;
        }
        return studiableRoundProgress.hashCode();
    }

    public final String toString() {
        return "Write(roundProgress=" + this.b + ")";
    }
}
