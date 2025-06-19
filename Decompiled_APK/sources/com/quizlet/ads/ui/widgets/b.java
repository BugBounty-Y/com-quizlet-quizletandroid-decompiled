package com.quizlet.ads.ui.widgets;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class b extends d {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        ((b) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return Long.hashCode(5000L) + d0.b(R.string.learn_ads_button_enabled, Integer.hashCode(R.string.learn_ads_button_count_down) * 31, 31);
    }

    public final String toString() {
        return "DisabledWithCountDown(disabledTextResource=2132018438, enabledTextResource=2132018439, millisInFuture=5000)";
    }
}
