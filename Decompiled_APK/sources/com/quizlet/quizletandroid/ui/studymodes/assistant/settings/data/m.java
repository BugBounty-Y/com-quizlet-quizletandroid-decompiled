package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.studysetting.data.GradingSettingsValues;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements o {
    public final kotlinx.collections.immutable.c a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final boolean j;
    public final boolean k;
    public final boolean l;
    public final GradingSettingsValues m;
    public final com.quizlet.qutils.language.e n;
    public final com.quizlet.qutils.language.e o;
    public final boolean p;
    public final boolean q;
    public final boolean r;

    public m(kotlinx.collections.immutable.c enabledGradingOptions, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8, boolean z9, boolean z10, boolean z11, GradingSettingsValues gradingSettingsValues, com.quizlet.qutils.language.e termValue, com.quizlet.qutils.language.e definitionValue, boolean z12, boolean z13, boolean z14) {
        Intrinsics.checkNotNullParameter(enabledGradingOptions, "enabledGradingOptions");
        Intrinsics.checkNotNullParameter(gradingSettingsValues, "gradingSettingsValues");
        Intrinsics.checkNotNullParameter(termValue, "termValue");
        Intrinsics.checkNotNullParameter(definitionValue, "definitionValue");
        this.a = enabledGradingOptions;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = z4;
        this.f = z5;
        this.g = z6;
        this.h = z7;
        this.i = z8;
        this.j = z9;
        this.k = z10;
        this.l = z11;
        this.m = gradingSettingsValues;
        this.n = termValue;
        this.o = definitionValue;
        this.p = z12;
        this.q = z13;
        this.r = z14;
    }

    public static m a(m mVar, boolean z, int i) {
        boolean z2 = (i & 1024) != 0 ? mVar.k : false;
        boolean z3 = (i & 2048) != 0 ? mVar.l : z;
        kotlinx.collections.immutable.c enabledGradingOptions = mVar.a;
        Intrinsics.checkNotNullParameter(enabledGradingOptions, "enabledGradingOptions");
        GradingSettingsValues gradingSettingsValues = mVar.m;
        Intrinsics.checkNotNullParameter(gradingSettingsValues, "gradingSettingsValues");
        com.quizlet.qutils.language.e termValue = mVar.n;
        Intrinsics.checkNotNullParameter(termValue, "termValue");
        com.quizlet.qutils.language.e definitionValue = mVar.o;
        Intrinsics.checkNotNullParameter(definitionValue, "definitionValue");
        return new m(enabledGradingOptions, mVar.b, mVar.c, mVar.d, mVar.e, mVar.f, mVar.g, mVar.h, mVar.i, mVar.j, z2, z3, gradingSettingsValues, termValue, definitionValue, mVar.p, mVar.q, mVar.r);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && this.b == mVar.b && this.c == mVar.c && this.d == mVar.d && this.e == mVar.e && this.f == mVar.f && this.g == mVar.g && this.h == mVar.h && this.i == mVar.i && this.j == mVar.j && this.k == mVar.k && this.l == mVar.l && Intrinsics.b(this.m, mVar.m) && Intrinsics.b(this.n, mVar.n) && Intrinsics.b(this.o, mVar.o) && this.p == mVar.p && this.q == mVar.q && this.r == mVar.r;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.r) + d0.g(d0.g((this.o.hashCode() + ((this.n.hashCode() + ((this.m.hashCode() + d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k), 31, this.l)) * 31)) * 31)) * 31, 31, this.p), 31, this.q);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(enabledGradingOptions=");
        sb.append(this.a);
        sb.append(", shuffleEnabled=");
        sb.append(this.b);
        sb.append(", audioEnabled=");
        sb.append(this.c);
        sb.append(", retypeEnabled=");
        sb.append(this.d);
        sb.append(", answerWithTermEnabled=");
        sb.append(this.e);
        sb.append(", answerWithDefinitionEnabled=");
        sb.append(this.f);
        sb.append(", answerWithLocationEnabled=");
        sb.append(this.g);
        sb.append(", showFlashcardsEnabled=");
        sb.append(this.h);
        sb.append(", showMultipleChoiceQuestionsEnabled=");
        sb.append(this.i);
        sb.append(", showWrittenQuestionsEnabled=");
        sb.append(this.j);
        sb.append(", isGuidanceEnabled=");
        sb.append(this.k);
        sb.append(", showRestartLearnModal=");
        sb.append(this.l);
        sb.append(", gradingSettingsValues=");
        sb.append(this.m);
        sb.append(", termValue=");
        sb.append(this.n);
        sb.append(", definitionValue=");
        sb.append(this.o);
        sb.append(", hasDiagram=");
        sb.append(this.p);
        sb.append(", writeEnabled=");
        sb.append(this.q);
        sb.append(", showNewGradingOptions=");
        return android.support.v4.media.session.a.o(")", sb, this.r);
    }
}
