package com.quizlet.features.practicetest.results.data;

import androidx.compose.animation.d0;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements w {
    public final y a;
    public final List b;
    public final kotlinx.collections.immutable.e c;
    public final LinkedHashMap d;
    public final PracticeTestConfigurationData e;
    public final boolean f;
    public final boolean g;
    public final int h;

    public t(y resultsScoreState, List questions, kotlinx.collections.immutable.e questionStatusList, LinkedHashMap questionCounts, PracticeTestConfigurationData practiceTestConfigurationData, boolean z, boolean z2, int i) {
        Intrinsics.checkNotNullParameter(resultsScoreState, "resultsScoreState");
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(questionStatusList, "questionStatusList");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        Intrinsics.checkNotNullParameter(practiceTestConfigurationData, "practiceTestConfigurationData");
        this.a = resultsScoreState;
        this.b = questions;
        this.c = questionStatusList;
        this.d = questionCounts;
        this.e = practiceTestConfigurationData;
        this.f = z;
        this.g = z2;
        this.h = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return this.a.equals(tVar.a) && Intrinsics.b(this.b, tVar.b) && Intrinsics.b(this.c, tVar.c) && this.d.equals(tVar.d) && this.e.equals(tVar.e) && this.f == tVar.f && this.g == tVar.g && this.h == tVar.h;
    }

    public final int hashCode() {
        return Integer.hashCode(this.h) + d0.g(d0.g((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b)) * 31)) * 31)) * 31, 31, this.f), 31, this.g);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(resultsScoreState=");
        sb.append(this.a);
        sb.append(", questions=");
        sb.append(this.b);
        sb.append(", questionStatusList=");
        sb.append(this.c);
        sb.append(", questionCounts=");
        sb.append(this.d);
        sb.append(", practiceTestConfigurationData=");
        sb.append(this.e);
        sb.append(", hasUnsupportedQuestionTypes=");
        sb.append(this.f);
        sb.append(", canUsePracticeTestsFeature=");
        sb.append(this.g);
        sb.append(", freeTrialDays=");
        return android.support.v4.media.session.a.r(sb, this.h, ")");
    }
}
