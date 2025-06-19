package com.quizlet.learn.data;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4538c extends AbstractC4540e {
    public final Integer d;
    public final com.quizlet.learn.ads.g e;
    public final com.quizlet.learn.ads.g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4538c(Integer num, com.quizlet.learn.ads.g onPrimaryCtaClick, com.quizlet.learn.ads.g onSecondaryCtaClick) {
        super(R.string.learn_end_hardtermsandtestmode_header, R.string.learn_end_hardtermsandtestmode_subheader, onPrimaryCtaClick, onSecondaryCtaClick, false);
        Intrinsics.checkNotNullParameter(onPrimaryCtaClick, "onPrimaryCtaClick");
        Intrinsics.checkNotNullParameter(onSecondaryCtaClick, "onSecondaryCtaClick");
        this.d = num;
        this.e = onPrimaryCtaClick;
        this.f = onSecondaryCtaClick;
    }

    @Override // com.quizlet.learn.data.AbstractC4540e
    public final Function0 a() {
        return this.e;
    }

    @Override // com.quizlet.learn.data.AbstractC4540e
    public final Function0 b() {
        return this.f;
    }

    @Override // com.quizlet.learn.data.AbstractC4540e
    public final Integer d() {
        return Integer.valueOf(R.string.learn_end_practice_more_button);
    }

    @Override // com.quizlet.learn.data.AbstractC4540e
    public final Integer e() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4538c)) {
            return false;
        }
        C4538c c4538c = (C4538c) obj;
        c4538c.getClass();
        return Integer.valueOf(R.string.learn_end_practice_more_button).equals(Integer.valueOf(R.string.learn_end_practice_more_button)) && Intrinsics.b(this.d, c4538c.d) && this.e.equals(c4538c.e) && this.f.equals(c4538c.f);
    }

    public final int hashCode() {
        int iHashCode = Integer.valueOf(R.string.learn_end_practice_more_button).hashCode() * 31;
        Integer num = this.d;
        return this.f.hashCode() + ((this.e.hashCode() + ((iHashCode + (num == null ? 0 : num.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        return "HardTermsAndTestMode(primaryCta=" + Integer.valueOf(R.string.learn_end_practice_more_button) + ", secondaryCta=" + this.d + ", onPrimaryCtaClick=" + this.e + ", onSecondaryCtaClick=" + this.f + ")";
    }
}
