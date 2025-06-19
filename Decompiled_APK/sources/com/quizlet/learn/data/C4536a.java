package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4536a {
    public final int a;
    public final String b;

    public C4536a(int i, int i2, String emoji) {
        i = (i2 & 2) != 0 ? R.string.assistant_checkpoint_msg_percent_100_pat_on_the_back_on_reviewing_terms : i;
        emoji = (i2 & 8) != 0 ? "🤓" : emoji;
        Intrinsics.checkNotNullParameter(emoji, "emoji");
        this.a = i;
        this.b = emoji;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4536a)) {
            return false;
        }
        C4536a c4536a = (C4536a) obj;
        c4536a.getClass();
        return this.a == c4536a.a && Intrinsics.b(this.b, c4536a.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + d0.b(R.string.study_again, d0.b(this.a, Integer.hashCode(R.string.assistant_checkpoint_msg_percent_100_reaching_mastery) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(header=2132017382, subHeader=");
        sb.append(this.a);
        sb.append(", primaryCta=2132019806, emoji=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
