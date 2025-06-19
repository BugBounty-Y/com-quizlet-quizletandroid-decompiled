package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import androidx.compose.animation.d0;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements x {
    public final int a;
    public final int b;
    public final boolean c;
    public final ShowQuestion d;

    public q(int i, int i2, boolean z, ShowQuestion showQuestion) {
        Intrinsics.checkNotNullParameter(showQuestion, "showQuestion");
        this.a = i;
        this.b = i2;
        this.c = z;
        this.d = showQuestion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && this.b == qVar.b && this.c == qVar.c && Intrinsics.b(this.d, qVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g(d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31, this.c);
    }

    public final String toString() {
        return "QuestionViewState(currentQuestionIndex=" + this.a + ", questionCount=" + this.b + ", shouldShowKeyboard=" + this.c + ", showQuestion=" + this.d + ")";
    }
}
