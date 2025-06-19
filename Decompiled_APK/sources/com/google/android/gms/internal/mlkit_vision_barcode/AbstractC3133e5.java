package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcelable;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import assistantMode.refactored.types.FITBMCQBlankSegment;
import assistantMode.refactored.types.FITBTextSegment;
import assistantMode.refactored.types.FITBWrittenBlankSegment;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestion;
import assistantMode.refactored.types.FillInTheBlankQuestion;
import assistantMode.refactored.types.MixedOptionMatchingQuestion;
import assistantMode.refactored.types.MultipleChoiceQuestion;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestion;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.SeparatedOptionMatchingQuestion;
import assistantMode.refactored.types.SpellingQuestion;
import assistantMode.refactored.types.TrueFalseQuestion;
import assistantMode.refactored.types.WrittenQuestion;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.FillInTheBlankStudiableSegment;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.e5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3133e5 {
    /* JADX WARN: Removed duplicated region for block: B:134:0x02b4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final kotlin.jvm.functions.Function0 r24, final kotlin.jvm.functions.Function0 r25, final kotlin.jvm.functions.Function0 r26, final kotlin.jvm.functions.Function1 r27, final kotlin.jvm.functions.Function1 r28, final kotlin.jvm.functions.Function1 r29, final kotlin.jvm.functions.Function1 r30, final kotlin.jvm.functions.Function1 r31, final kotlin.jvm.functions.Function1 r32, final kotlin.jvm.functions.Function1 r33, final kotlin.jvm.functions.Function1 r34, androidx.compose.ui.n r35, com.quizlet.features.home.viewmodel.d r36, androidx.compose.runtime.InterfaceC0806l r37, final int r38) {
        /*
            Method dump skipped, instructions count: 773
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5.a(kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.ui.n, com.quizlet.features.home.viewmodel.d, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.features.home.data.u uVar, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(173053402);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(uVar) : c0814p2.h(uVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            nVar2 = nVar;
            i2 |= c0814p2.f(nVar2) ? 32 : 16;
        } else {
            nVar2 = nVar;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            AbstractC0725t3.a(nVar2, androidx.compose.runtime.internal.e.e(-1639262818, new androidx.navigation.compose.o(20, uVar, function1), c0814p2), null, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(-53420375, new com.quizlet.assembly.compose.input.m(14, uVar, function1), c0814p2), c0814p, ((i2 >> 3) & 14) | 805306416, 508);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 11, uVar, nVar, function1);
        }
    }

    public static StudiableQuestion c(assistantMode.refactored.types.d question, List shapes, List images) {
        StudiableQuestion fillInTheBlankStudiableQuestion;
        Parcelable text;
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(shapes, "shapes");
        Intrinsics.checkNotNullParameter(images, "images");
        if (question instanceof MultipleChoiceQuestion) {
            MultipleChoiceQuestion multipleChoiceQuestion = (MultipleChoiceQuestion) question;
            StudiableQuestionMetadata studiableQuestionMetadataE = com.quizlet.studiablemodels.grading.c.e(multipleChoiceQuestion.e, multipleChoiceQuestion.f, images);
            QuestionSectionData questionSectionDataD = com.quizlet.studiablemodels.grading.c.d(multipleChoiceQuestion.a, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE.c), shapes);
            List list = multipleChoiceQuestion.c;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(com.quizlet.studiablemodels.grading.c.d((QuestionElement) it2.next(), com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE.d), shapes));
            }
            QuestionElement questionElement = multipleChoiceQuestion.b;
            fillInTheBlankStudiableQuestion = new MultipleChoiceStudiableQuestion(questionSectionDataD, arrayList, questionElement != null ? com.quizlet.studiablemodels.grading.c.c(questionElement, shapes) : null, multipleChoiceQuestion.d, studiableQuestionMetadataE, com.google.android.gms.internal.mlkit_vision_camera.m3.c(multipleChoiceQuestion));
        } else if (question instanceof RevealSelfAssessmentQuestion) {
            RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) question;
            StudiableQuestionMetadata studiableQuestionMetadataE2 = com.quizlet.studiablemodels.grading.c.e(revealSelfAssessmentQuestion.d, revealSelfAssessmentQuestion.e, images);
            fillInTheBlankStudiableQuestion = new RevealSelfAssessmentStudiableQuestion(com.quizlet.studiablemodels.grading.c.d(revealSelfAssessmentQuestion.a, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE2.c), shapes), com.quizlet.studiablemodels.grading.c.d(revealSelfAssessmentQuestion.b, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE2.d), shapes), studiableQuestionMetadataE2, com.google.android.gms.internal.mlkit_vision_camera.m3.c(revealSelfAssessmentQuestion));
        } else if (question instanceof TrueFalseQuestion) {
            TrueFalseQuestion trueFalseQuestion = (TrueFalseQuestion) question;
            QuestionMetadata questionMetadata = trueFalseQuestion.c;
            kotlin.collections.K k = kotlin.collections.K.a;
            StudiableQuestionMetadata studiableQuestionMetadataE3 = com.quizlet.studiablemodels.grading.c.e(questionMetadata, trueFalseQuestion.d, k);
            fillInTheBlankStudiableQuestion = new TrueFalseStudiableQuestion(com.quizlet.studiablemodels.grading.c.d(trueFalseQuestion.a, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE3.c), k), com.quizlet.studiablemodels.grading.c.d(trueFalseQuestion.b, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE3.d), k), studiableQuestionMetadataE3, com.google.android.gms.internal.mlkit_vision_camera.m3.c(trueFalseQuestion));
        } else if (question instanceof WrittenQuestion) {
            WrittenQuestion writtenQuestion = (WrittenQuestion) question;
            StudiableQuestionMetadata studiableQuestionMetadataE4 = com.quizlet.studiablemodels.grading.c.e(writtenQuestion.d, writtenQuestion.e, images);
            QuestionSectionData questionSectionDataD2 = com.quizlet.studiablemodels.grading.c.d(writtenQuestion.a, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE4.c), shapes);
            String strC = com.google.android.gms.internal.mlkit_vision_camera.m3.c(writtenQuestion);
            QuestionElement questionElement2 = writtenQuestion.c;
            QuestionSectionData questionSectionDataC = questionElement2 != null ? com.quizlet.studiablemodels.grading.c.c(questionElement2, kotlin.collections.K.a) : null;
            DefaultQuestionSectionData defaultQuestionSectionData = questionSectionDataC instanceof DefaultQuestionSectionData ? (DefaultQuestionSectionData) questionSectionDataC : null;
            fillInTheBlankStudiableQuestion = new WrittenStudiableQuestion(questionSectionDataD2, studiableQuestionMetadataE4, strC, defaultQuestionSectionData != null ? defaultQuestionSectionData.a : null);
        } else if (question instanceof MixedOptionMatchingQuestion) {
            MixedOptionMatchingQuestion mixedOptionMatchingQuestion = (MixedOptionMatchingQuestion) question;
            StudiableQuestionMetadata studiableQuestionMetadataE5 = com.quizlet.studiablemodels.grading.c.e(mixedOptionMatchingQuestion.b, mixedOptionMatchingQuestion.c, images);
            List list2 = mixedOptionMatchingQuestion.a;
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(list2, 10));
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList2.add(com.quizlet.studiablemodels.grading.c.c((QuestionElement) it3.next(), shapes));
            }
            fillInTheBlankStudiableQuestion = new MixedOptionMatchingStudiableQuestion(arrayList2, studiableQuestionMetadataE5, com.google.android.gms.internal.mlkit_vision_camera.m3.c(mixedOptionMatchingQuestion));
        } else {
            if (!(question instanceof FillInTheBlankQuestion)) {
                if (!(question instanceof SeparatedOptionMatchingQuestion) && !(question instanceof SpellingQuestion) && !(question instanceof FillInTheBlankMultipleChoiceQuestion) && !(question instanceof MultipleChoiceSelectAllThatApplyQuestion)) {
                    throw new NoWhenBranchMatchedException();
                }
                throw new RuntimeException("Unsupported question type: " + question.a());
            }
            FillInTheBlankQuestion fillInTheBlankQuestion = (FillInTheBlankQuestion) question;
            QuestionMetadata questionMetadata2 = fillInTheBlankQuestion.c;
            kotlin.collections.K k2 = kotlin.collections.K.a;
            StudiableQuestionMetadata studiableQuestionMetadataE6 = com.quizlet.studiablemodels.grading.c.e(questionMetadata2, fillInTheBlankQuestion.f, k2);
            QuestionSectionData questionSectionDataD3 = com.quizlet.studiablemodels.grading.c.d(fillInTheBlankQuestion.a, com.quizlet.studiablemodels.grading.c.a(studiableQuestionMetadataE6.c), k2);
            String strC2 = com.google.android.gms.internal.mlkit_vision_camera.m3.c(fillInTheBlankQuestion);
            List<assistantMode.refactored.types.b> list3 = fillInTheBlankQuestion.b;
            ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(list3, 10));
            for (assistantMode.refactored.types.b bVar : list3) {
                if (bVar instanceof FITBTextSegment) {
                    text = new FillInTheBlankStudiableSegment.Text(((FITBTextSegment) bVar).a.a);
                } else {
                    if (!(bVar instanceof FITBWrittenBlankSegment)) {
                        if (!(bVar instanceof FITBMCQBlankSegment)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        throw new RuntimeException("Unsupported FillInTheBlankSegment: " + bVar);
                    }
                    text = FillInTheBlankStudiableSegment.Blank.a;
                }
                arrayList3.add(text);
            }
            fillInTheBlankStudiableQuestion = new FillInTheBlankStudiableQuestion(questionSectionDataD3, studiableQuestionMetadataE6, strC2, arrayList3);
        }
        Map map = question.getMetadata().h;
        fillInTheBlankStudiableQuestion.a = map != null ? AbstractC3097a5.e(map) : null;
        return fillInTheBlankStudiableQuestion;
    }

    public static final Object d(androidx.compose.ui.semantics.k kVar, androidx.compose.ui.semantics.u uVar) {
        Object obj = kVar.a.get(uVar);
        if (obj == null) {
            return null;
        }
        return obj;
    }
}
