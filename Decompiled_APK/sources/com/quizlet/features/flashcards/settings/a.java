package com.quizlet.features.flashcards.settings;

import androidx.appcompat.app.y;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends y {
    public final ArrayList d;
    public final assistantMode.enums.m e;
    public final com.quizlet.qutils.string.g f;
    public final com.quizlet.qutils.string.g g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ArrayList cardSides, assistantMode.enums.m selectedCardSide, com.quizlet.qutils.string.g termStringResData, com.quizlet.qutils.string.g definitionStringResData) {
        super(selectedCardSide, cardSides);
        Intrinsics.checkNotNullParameter(cardSides, "cardSides");
        Intrinsics.checkNotNullParameter(selectedCardSide, "selectedCardSide");
        Intrinsics.checkNotNullParameter(termStringResData, "termStringResData");
        Intrinsics.checkNotNullParameter(definitionStringResData, "definitionStringResData");
        this.d = cardSides;
        this.e = selectedCardSide;
        this.f = termStringResData;
        this.g = definitionStringResData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.d, aVar.d) && this.e == aVar.e && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + assistantMode.refactored.a.e(this.e, this.d.hashCode() * 31, 31)) * 31);
    }

    @Override // androidx.appcompat.app.y
    public final com.quizlet.qutils.string.g m(int i) {
        int iOrdinal = ((assistantMode.enums.m) this.d.get(i)).ordinal();
        if (iOrdinal == 0) {
            return this.f;
        }
        if (iOrdinal == 1) {
            return this.g;
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        return new com.quizlet.qutils.string.f(R.string.location, C4933y.P(args));
    }

    @Override // androidx.appcompat.app.y
    public final String toString() {
        return "CardSideSegmentedControlState(cardSides=" + this.d + ", selectedCardSide=" + this.e + ", termStringResData=" + this.f + ", definitionStringResData=" + this.g + ")";
    }
}
