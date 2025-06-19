package com.quizlet.features.match.studyengine;

import com.quizlet.features.match.data.EnumC4369z;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements h {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        MixedOptionMatchingStudiableQuestion matchingStudiableQuestion = (MixedOptionMatchingStudiableQuestion) obj;
        Intrinsics.checkNotNullParameter(matchingStudiableQuestion, "matchingStudiableQuestion");
        return matchingStudiableQuestion.c.b() ? EnumC4369z.b : EnumC4369z.a;
    }
}
