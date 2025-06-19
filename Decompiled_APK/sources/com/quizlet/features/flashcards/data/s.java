package com.quizlet.features.flashcards.data;

import com.google.android.gms.internal.ads.N;
import com.quizlet.features.flashcards.C4242p;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class s extends N {
    public final C4242p e;
    public final C4242p f;
    public final C4242p g;
    public final int h;
    public final com.quizlet.qutils.string.f i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(C4242p primaryCtaOnClick, C4242p secondaryCtaOnClick, C4242p tertiaryCtaOnClick) {
        super(R.drawable.img_fc_incomplete, new n(R.string.flashcards_summary_continue_cta, 4, primaryCtaOnClick), new n(R.string.flashcards_summary_learn_cta, 12, secondaryCtaOnClick), new n(R.string.flashcards_next_steps_restart_title, 12, tertiaryCtaOnClick));
        Intrinsics.checkNotNullParameter(primaryCtaOnClick, "primaryCtaOnClick");
        Intrinsics.checkNotNullParameter(secondaryCtaOnClick, "secondaryCtaOnClick");
        Intrinsics.checkNotNullParameter(tertiaryCtaOnClick, "tertiaryCtaOnClick");
        this.e = primaryCtaOnClick;
        this.f = secondaryCtaOnClick;
        this.g = tertiaryCtaOnClick;
        this.h = R.string.flashcards_summary_sorted_incomplete_header;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.i = new com.quizlet.qutils.string.f(R.string.flashcards_summary_sorted_incomplete_message, C4933y.P(args));
    }

    @Override // com.google.android.gms.internal.ads.N
    public final int a() {
        return this.h;
    }

    @Override // com.google.android.gms.internal.ads.N
    public final com.quizlet.qutils.string.f b() {
        return this.i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.e, sVar.e) && Intrinsics.b(this.f, sVar.f) && Intrinsics.b(this.g, sVar.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + (this.e.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "IncompleteSortedMode(primaryCtaOnClick=" + this.e + ", secondaryCtaOnClick=" + this.f + ", tertiaryCtaOnClick=" + this.g + ")";
    }
}
