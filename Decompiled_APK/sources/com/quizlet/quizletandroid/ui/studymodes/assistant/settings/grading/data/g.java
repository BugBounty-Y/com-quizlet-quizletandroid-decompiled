package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class g implements i {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;

    public g(boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6) {
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
        this.e = z5;
        this.f = z6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && this.b == gVar.b && this.c == gVar.c && this.d == gVar.d && this.e == gVar.e && this.f == gVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.g(d0.g(d0.g(d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, false), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(ignoreTyposEnabled=");
        sb.append(this.a);
        sb.append(", partialAnswersEnabled=");
        sb.append(this.b);
        sb.append(", smartGradingEnabled=");
        sb.append(this.c);
        sb.append(", isProvideFeedbackButtonVisible=");
        sb.append(this.d);
        sb.append(", isIgnoreTyposOptionVisible=false, isSmartGradingOptionVisible=");
        sb.append(this.e);
        sb.append(", isPartialAnswerOptionVisible=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
