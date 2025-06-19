package com.quizlet.uicommon.ui.common.util;

import android.text.SpannableString;
import androidx.compose.animation.d0;
import com.quizlet.data.model.A0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final String a;
    public final SpannableString b;
    public final int c;
    public final A0 d;

    public e(String title, SpannableString description, int i, A0 modeButtonState) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(modeButtonState, "modeButtonState");
        this.a = title;
        this.b = description;
        this.c = i;
        this.d = modeButtonState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && this.c == eVar.c && this.d == eVar.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.b(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31);
    }

    public final String toString() {
        return "StudyModeNextStepData(title=" + this.a + ", description=" + ((Object) this.b) + ", image=" + this.c + ", modeButtonState=" + this.d + ")";
    }
}
