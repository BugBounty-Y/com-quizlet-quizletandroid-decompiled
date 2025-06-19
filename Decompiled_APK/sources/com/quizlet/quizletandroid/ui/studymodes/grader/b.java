package com.quizlet.quizletandroid.ui.studymodes.grader;

import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.grading.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final dagger.internal.a a;
    public final dagger.internal.a b;

    public b(dagger.internal.a learningAssistantStudyEngine, dagger.internal.a testStudyEngine) {
        Intrinsics.checkNotNullParameter(learningAssistantStudyEngine, "learningAssistantStudyEngine");
        Intrinsics.checkNotNullParameter(testStudyEngine, "testStudyEngine");
        this.a = learningAssistantStudyEngine;
        this.b = testStudyEngine;
    }

    public final d a(A1 type) {
        Intrinsics.checkNotNullParameter(type, "type");
        int i = a.a[type.ordinal()];
        if (i == 1 || i == 2) {
            Object obj = this.a.get();
            Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
            return (d) obj;
        }
        if (i == 3) {
            Object obj2 = this.b.get();
            Intrinsics.checkNotNullExpressionValue(obj2, "get(...)");
            return (d) obj2;
        }
        throw new IllegalArgumentException("Unsupported study mode type: " + type);
    }
}
