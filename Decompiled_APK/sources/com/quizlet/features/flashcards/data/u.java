package com.quizlet.features.flashcards.data;

import com.google.android.gms.internal.ads.N;
import com.quizlet.assembly.compose.buttons.C4089n;
import com.quizlet.assembly.compose.buttons.C4090o;
import com.quizlet.features.flashcards.C4242p;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class u extends N {
    public final boolean e;
    public final C4242p f;
    public final C4242p g;
    public final com.quizlet.explanations.textbook.ui.f h;
    public final int i;
    public final com.quizlet.qutils.string.f j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(boolean z, C4242p primaryCtaOnClick, C4242p secondaryCtaOnClick, com.quizlet.explanations.textbook.ui.f linearProgressEvent) {
        super(R.drawable.img_fc_complete, new n(R.string.flashcards_summary_learn_cta, primaryCtaOnClick, z ? new C4089n(linearProgressEvent) : C4090o.a, c.d), new n(R.string.flashcards_next_steps_restart_title, 12, secondaryCtaOnClick), null);
        Intrinsics.checkNotNullParameter(primaryCtaOnClick, "primaryCtaOnClick");
        Intrinsics.checkNotNullParameter(secondaryCtaOnClick, "secondaryCtaOnClick");
        Intrinsics.checkNotNullParameter(linearProgressEvent, "linearProgressEvent");
        this.e = z;
        this.f = primaryCtaOnClick;
        this.g = secondaryCtaOnClick;
        this.h = linearProgressEvent;
        this.i = R.string.flashcards_summary_unsorted_header;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.j = new com.quizlet.qutils.string.f(R.string.flashcards_summary_learn_message, C4933y.P(args));
    }

    @Override // com.google.android.gms.internal.ads.N
    public final int a() {
        return this.i;
    }

    @Override // com.google.android.gms.internal.ads.N
    public final com.quizlet.qutils.string.f b() {
        return this.j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return this.e == uVar.e && Intrinsics.b(this.f, uVar.f) && Intrinsics.b(this.g, uVar.g) && Intrinsics.b(this.h, uVar.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + (Boolean.hashCode(this.e) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "UnsortedMode(isAutoLaunchEnabled=" + this.e + ", primaryCtaOnClick=" + this.f + ", secondaryCtaOnClick=" + this.g + ", linearProgressEvent=" + this.h + ")";
    }
}
