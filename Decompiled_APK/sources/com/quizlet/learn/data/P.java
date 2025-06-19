package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.quizlet.data.model.C4127f1;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class P {
    public final QuestionSettings a;
    public final A1 b;
    public final boolean c;
    public final C4127f1 d;
    public final Map e;
    public final Map f;
    public final ExperimentConfiguration g;
    public final boolean h;

    public P(QuestionSettings settings, A1 studyModeType, boolean z, C4127f1 c4127f1, Map studiableMetadataByType, Map meteringData, ExperimentConfiguration experimentConfiguration, boolean z2) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        Intrinsics.checkNotNullParameter(studiableMetadataByType, "studiableMetadataByType");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        Intrinsics.checkNotNullParameter(experimentConfiguration, "experimentConfiguration");
        this.a = settings;
        this.b = studyModeType;
        this.c = z;
        this.d = c4127f1;
        this.e = studiableMetadataByType;
        this.f = meteringData;
        this.g = experimentConfiguration;
        this.h = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof P)) {
            return false;
        }
        P p = (P) obj;
        return Intrinsics.b(this.a, p.a) && this.b == p.b && this.c == p.c && Intrinsics.b(this.d, p.d) && Intrinsics.b(this.e, p.e) && Intrinsics.b(this.f, p.f) && Intrinsics.b(this.g, p.g) && this.h == p.h;
    }

    public final int hashCode() {
        int iG = d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
        C4127f1 c4127f1 = this.d;
        return Boolean.hashCode(this.h) + ((this.g.hashCode() + assistantMode.refactored.a.d(assistantMode.refactored.a.d((iG + (c4127f1 == null ? 0 : c4127f1.hashCode())) * 31, 31, this.e), 31, this.f)) * 31);
    }

    public final String toString() {
        return "StepConfiguration(settings=" + this.a + ", studyModeType=" + this.b + ", hasNewSettings=" + this.c + ", crossModeProgressReset=" + this.d + ", studiableMetadataByType=" + this.e + ", meteringData=" + this.f + ", experimentConfiguration=" + this.g + ", easierQuestion=" + this.h + ")";
    }
}
