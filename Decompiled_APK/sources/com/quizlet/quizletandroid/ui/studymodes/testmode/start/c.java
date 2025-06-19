package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends B {
    public final String a;
    public final androidx.compose.ui.text.input.A b;
    public final int c;
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y d;
    public final j e;
    public final j f;
    public final j g;
    public final j h;
    public final boolean i;
    public final boolean j;
    public final Integer k;
    public final C4757a l;

    public c(String setTitle, androidx.compose.ui.text.input.A questionCount, int i, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y questionCountChanged, j instantFeedbackSwitchData, j trueFalseSwitchData, j mcqSwitchData, j writtenSwitchData, boolean z, boolean z2, Integer num, C4757a answerPromptConfiguration) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(questionCount, "questionCount");
        Intrinsics.checkNotNullParameter(questionCountChanged, "questionCountChanged");
        Intrinsics.checkNotNullParameter(instantFeedbackSwitchData, "instantFeedbackSwitchData");
        Intrinsics.checkNotNullParameter(trueFalseSwitchData, "trueFalseSwitchData");
        Intrinsics.checkNotNullParameter(mcqSwitchData, "mcqSwitchData");
        Intrinsics.checkNotNullParameter(writtenSwitchData, "writtenSwitchData");
        Intrinsics.checkNotNullParameter(answerPromptConfiguration, "answerPromptConfiguration");
        this.a = setTitle;
        this.b = questionCount;
        this.c = i;
        this.d = questionCountChanged;
        this.e = instantFeedbackSwitchData;
        this.f = trueFalseSwitchData;
        this.g = mcqSwitchData;
        this.h = writtenSwitchData;
        this.i = z;
        this.j = z2;
        this.k = num;
        this.l = answerPromptConfiguration;
    }

    public static c a(c cVar, androidx.compose.ui.text.input.A a, j jVar, j jVar2, j jVar3, j jVar4, boolean z, C4757a c4757a, int i) {
        String setTitle = cVar.a;
        if ((i & 2) != 0) {
            a = cVar.b;
        }
        androidx.compose.ui.text.input.A questionCount = a;
        int i2 = cVar.c;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y questionCountChanged = cVar.d;
        j instantFeedbackSwitchData = (i & 16) != 0 ? cVar.e : jVar;
        j trueFalseSwitchData = (i & 32) != 0 ? cVar.f : jVar2;
        j mcqSwitchData = (i & 64) != 0 ? cVar.g : jVar3;
        j writtenSwitchData = (i & 128) != 0 ? cVar.h : jVar4;
        boolean z2 = cVar.i;
        boolean z3 = (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? cVar.j : z;
        Integer num = cVar.k;
        C4757a answerPromptConfiguration = (i & 2048) != 0 ? cVar.l : c4757a;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(questionCount, "questionCount");
        Intrinsics.checkNotNullParameter(questionCountChanged, "questionCountChanged");
        Intrinsics.checkNotNullParameter(instantFeedbackSwitchData, "instantFeedbackSwitchData");
        Intrinsics.checkNotNullParameter(trueFalseSwitchData, "trueFalseSwitchData");
        Intrinsics.checkNotNullParameter(mcqSwitchData, "mcqSwitchData");
        Intrinsics.checkNotNullParameter(writtenSwitchData, "writtenSwitchData");
        Intrinsics.checkNotNullParameter(answerPromptConfiguration, "answerPromptConfiguration");
        return new c(setTitle, questionCount, i2, questionCountChanged, instantFeedbackSwitchData, trueFalseSwitchData, mcqSwitchData, writtenSwitchData, z2, z3, num, answerPromptConfiguration);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a.equals(cVar.a) && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c && this.d.equals(cVar.d) && Intrinsics.b(this.e, cVar.e) && Intrinsics.b(this.f, cVar.f) && Intrinsics.b(this.g, cVar.g) && Intrinsics.b(this.h, cVar.h) && this.i == cVar.i && this.j == cVar.j && Intrinsics.b(this.k, cVar.k) && Intrinsics.b(this.l, cVar.l);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.b(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31)) * 31)) * 31)) * 31)) * 31)) * 31, 31, this.i), 31, this.j);
        Integer num = this.k;
        return this.l.hashCode() + ((iG + (num == null ? 0 : num.hashCode())) * 31);
    }

    public final String toString() {
        return "LoadedViewState(setTitle=" + this.a + ", questionCount=" + this.b + ", maxQuestionCount=" + this.c + ", questionCountChanged=" + this.d + ", instantFeedbackSwitchData=" + this.e + ", trueFalseSwitchData=" + this.f + ", mcqSwitchData=" + this.g + ", writtenSwitchData=" + this.h + ", isMetered=" + this.i + ", isStartEnabled=" + this.j + ", lastTestScore=" + this.k + ", answerPromptConfiguration=" + this.l + ")";
    }
}
