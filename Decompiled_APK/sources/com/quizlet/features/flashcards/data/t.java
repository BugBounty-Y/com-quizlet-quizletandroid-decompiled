package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;

/* loaded from: classes2.dex */
public final class t extends AbstractC3146g0 {
    public final boolean b;
    public final int c;
    public final int d;
    public final int e;

    public t(boolean z, int i, int i2, int i3) {
        this.b = z;
        this.c = i;
        this.d = i2;
        this.e = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return this.b == tVar.b && this.c == tVar.c && this.d == tVar.d && this.e == tVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + d0.b(this.e, d0.b(this.d, d0.b(this.c, Boolean.hashCode(this.b) * 31, 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SummaryCardData(isSortingEnabled=");
        sb.append(this.b);
        sb.append(", numOfLearnedTerms=");
        sb.append(this.c);
        sb.append(", numOfRemainingTerms=");
        sb.append(this.d);
        sb.append(", currentRound=");
        return android.support.v4.media.session.a.r(sb, this.e, ", isNewExperimentLogic=false)");
    }
}
