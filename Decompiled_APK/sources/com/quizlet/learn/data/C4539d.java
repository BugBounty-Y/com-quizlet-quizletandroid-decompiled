package com.quizlet.learn.data;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4539d extends AbstractC4540e {
    public final Integer d;
    public final com.quizlet.learn.ads.g e;
    public final com.quizlet.learn.ads.g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4539d(Integer num, com.quizlet.learn.ads.g onPrimaryCtaClick, com.quizlet.learn.ads.g onSecondaryCtaClick) {
        super(R.string.learn_end_hardtermsandtestmode_post_header, R.string.learn_end_hardtermsandtestmode_post_subheader, onPrimaryCtaClick, onSecondaryCtaClick, true);
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
        return this.d;
    }

    @Override // com.quizlet.learn.data.AbstractC4540e
    public final Integer e() {
        return Integer.valueOf(R.string.learn_end_practice_more_button);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4539d)) {
            return false;
        }
        C4539d c4539d = (C4539d) obj;
        return Intrinsics.b(this.d, c4539d.d) && Integer.valueOf(R.string.learn_end_practice_more_button).equals(Integer.valueOf(R.string.learn_end_practice_more_button)) && this.e.equals(c4539d.e) && this.f.equals(c4539d.f);
    }

    public final int hashCode() {
        Integer num = this.d;
        return this.f.hashCode() + ((this.e.hashCode() + ((Integer.valueOf(R.string.learn_end_practice_more_button).hashCode() + ((num == null ? 0 : num.hashCode()) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "PostHardTermsAndTestMode(primaryCta=" + this.d + ", secondaryCta=" + Integer.valueOf(R.string.learn_end_practice_more_button) + ", onPrimaryCtaClick=" + this.e + ", onSecondaryCtaClick=" + this.f + ")";
    }
}
