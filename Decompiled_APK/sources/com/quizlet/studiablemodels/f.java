package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import assistantMode.enums.k;
import assistantMode.enums.m;
import com.comscore.streaming.EventType;
import com.quizlet.generated.enums.EnumC4508o1;
import com.quizlet.studiablemodels.grading.FillInTheBlankResponse;
import com.quizlet.studiablemodels.grading.MatchingGameResponse;
import com.quizlet.studiablemodels.grading.MultipleChoiceResponse;
import com.quizlet.studiablemodels.grading.PGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.PLocalGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.PLongtextGradingResult;
import com.quizlet.studiablemodels.grading.PSmartGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.RevealSelfAssessmentResponse;
import com.quizlet.studiablemodels.grading.StudiableQuestionFeedback;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        ArrayList arrayList;
        LinkedHashMap linkedHashMap;
        boolean z;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new RevealSelfAssessmentStudiableQuestion((QuestionSectionData) parcel.readParcelable(RevealSelfAssessmentStudiableQuestion.class.getClassLoader()), (QuestionSectionData) parcel.readParcelable(RevealSelfAssessmentStudiableQuestion.class.getClassLoader()), StudiableQuestionMetadata.CREATOR.createFromParcel(parcel), parcel.readString());
            case 1:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new RoundResultItem(parcel.readLong(), parcel.readInt() != 0);
            case 2:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableAudio(parcel.readString());
            case 3:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                AssistantCheckpointProgressState assistantCheckpointProgressStateCreateFromParcel = AssistantCheckpointProgressState.CREATOR.createFromParcel(parcel);
                boolean z2 = parcel.readInt() != 0;
                if (parcel.readInt() == 0) {
                    arrayList = null;
                } else {
                    int i = parcel.readInt();
                    arrayList = new ArrayList(i);
                    for (int i2 = 0; i2 != i; i2++) {
                        arrayList.add(RoundResultItem.CREATOR.createFromParcel(parcel));
                    }
                }
                return new StudiableCheckpoint(assistantCheckpointProgressStateCreateFromParcel, z2, arrayList, parcel.readInt() != 0 ? StudiableMeteringData.CREATOR.createFromParcel(parcel) : null);
            case 4:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableDiagramImage(parcel.readLong(), StudiableImage.CREATOR.createFromParcel(parcel));
            case 5:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableDiagramShape(parcel.readString());
            case 6:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableImage(parcel.readString(), parcel.readInt(), parcel.readString(), parcel.readString(), parcel.readInt());
            case 7:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableLearnPaywall(parcel.readInt() == 0 ? null : StudiableMeteringData.CREATOR.createFromParcel(parcel));
            case 8:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return StudiableMetadataCategory.valueOf(parcel.readString());
            case 9:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return StudiableMetadataType.valueOf(parcel.readString());
            case 10:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableMeteringData(com.quizlet.shared.enums.h.valueOf(parcel.readString()), parcel.readInt() == 0 ? null : Integer.valueOf(parcel.readInt()), parcel.readInt() != 0 ? Integer.valueOf(parcel.readInt()) : null);
            case 11:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableQuestionMetadata(k.valueOf(parcel.readString()), parcel.readLong(), m.valueOf(parcel.readString()), m.valueOf(parcel.readString()), parcel.readInt() == 0 ? null : StudiableDiagramImage.CREATOR.createFromParcel(parcel), parcel.readInt() != 0 ? StudiableQuestionSource.CREATOR.createFromParcel(parcel) : null);
            case 12:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableQuestionSource(StudiableMetadataType.CREATOR.createFromParcel(parcel), parcel.readInt() == 0 ? null : StudiableMetadataCategory.CREATOR.createFromParcel(parcel), parcel.readInt() != 0 ? Integer.valueOf(parcel.readInt()) : null);
            case 13:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableRoundProgress(parcel.readInt(), parcel.readInt());
            case 14:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableTaskProgress(parcel.readInt(), parcel.readInt());
            case 15:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableTaskTotalProgress(parcel.readDouble());
            case 16:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableText(parcel.readString(), parcel.readString(), parcel.readString());
            case 17:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudiableTotalProgress(StudiableWriteMasteryBuckets.CREATOR.createFromParcel(parcel), parcel.readDouble());
            case 18:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i3 = parcel.readInt();
                ArrayList arrayList2 = new ArrayList(i3);
                for (int i4 = 0; i4 != i3; i4++) {
                    arrayList2.add(Long.valueOf(parcel.readLong()));
                }
                int i5 = parcel.readInt();
                ArrayList arrayList3 = new ArrayList(i5);
                for (int i6 = 0; i6 != i5; i6++) {
                    arrayList3.add(Long.valueOf(parcel.readLong()));
                }
                return new StudiableWriteMasteryBuckets(arrayList2, arrayList3);
            case 19:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new TrueFalseStudiableQuestion((QuestionSectionData) parcel.readParcelable(TrueFalseStudiableQuestion.class.getClassLoader()), (QuestionSectionData) parcel.readParcelable(TrueFalseStudiableQuestion.class.getClassLoader()), StudiableQuestionMetadata.CREATOR.createFromParcel(parcel), parcel.readString());
            case 20:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new WrittenStudiableQuestion((QuestionSectionData) parcel.readParcelable(WrittenStudiableQuestion.class.getClassLoader()), StudiableQuestionMetadata.CREATOR.createFromParcel(parcel), parcel.readString(), parcel.readInt() == 0 ? null : StudiableText.CREATOR.createFromParcel(parcel));
            case 21:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new FillInTheBlankResponse(parcel.createStringArrayList());
            case EventType.WINDOW_STATE /* 22 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new MatchingGameResponse(parcel.readInt(), parcel.readInt());
            case EventType.AUDIO /* 23 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new MultipleChoiceResponse(parcel.readInt());
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                parcel.readInt();
                return PLocalGradedAnswerMetadata.b;
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new PLongtextGradingResult(EnumC4508o1.valueOf(parcel.readString()), parcel.readDouble(), parcel.readString(), parcel.readInt() == 0 ? null : Double.valueOf(parcel.readDouble()), parcel.readString());
            case EventType.CDN /* 26 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new PSmartGradedAnswerMetadata(parcel.readInt() == 0 ? null : PLongtextGradingResult.CREATOR.createFromParcel(parcel), parcel.readInt() != 0, parcel.readLong(), parcel.readLong(), parcel.readInt() != 0 ? Long.valueOf(parcel.readLong()) : null);
            case 27:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new RevealSelfAssessmentResponse(com.quizlet.studiablemodels.grading.a.valueOf(parcel.readString()));
            case 28:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                StudiableQuestionResponse studiableQuestionResponse = (StudiableQuestionResponse) parcel.readParcelable(StudiableQuestionFeedback.class.getClassLoader());
                StudiableQuestionResponse studiableQuestionResponse2 = (StudiableQuestionResponse) parcel.readParcelable(StudiableQuestionFeedback.class.getClassLoader());
                QuestionSectionData questionSectionData = (QuestionSectionData) parcel.readParcelable(StudiableQuestionFeedback.class.getClassLoader());
                if (parcel.readInt() == 0) {
                    linkedHashMap = null;
                } else {
                    int i7 = parcel.readInt();
                    LinkedHashMap linkedHashMap2 = new LinkedHashMap(i7);
                    for (int i8 = 0; i8 != i7; i8++) {
                        linkedHashMap2.put(Integer.valueOf(parcel.readInt()), parcel.readParcelable(StudiableQuestionFeedback.class.getClassLoader()));
                    }
                    linkedHashMap = linkedHashMap2;
                }
                return new StudiableQuestionFeedback(studiableQuestionResponse, studiableQuestionResponse2, questionSectionData, linkedHashMap);
            default:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                boolean z3 = false;
                if (parcel.readInt() != 0) {
                    z = false;
                    z3 = true;
                } else {
                    z = false;
                }
                StudiableQuestionFeedback studiableQuestionFeedbackCreateFromParcel = StudiableQuestionFeedback.CREATOR.createFromParcel(parcel);
                Boolean boolValueOf = parcel.readInt() == 0 ? null : Boolean.valueOf(parcel.readInt() != 0 ? true : z);
                Boolean boolValueOf2 = parcel.readInt() != 0 ? Boolean.valueOf(parcel.readInt() != 0 ? true : z) : null;
                if (parcel.readInt() != 0) {
                    z = true;
                }
                return new StudiableQuestionGradedAnswer(z3, studiableQuestionFeedbackCreateFromParcel, boolValueOf, boolValueOf2, z, (PGradedAnswerMetadata) parcel.readParcelable(StudiableQuestionGradedAnswer.class.getClassLoader()));
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new RevealSelfAssessmentStudiableQuestion[i];
            case 1:
                return new RoundResultItem[i];
            case 2:
                return new StudiableAudio[i];
            case 3:
                return new StudiableCheckpoint[i];
            case 4:
                return new StudiableDiagramImage[i];
            case 5:
                return new StudiableDiagramShape[i];
            case 6:
                return new StudiableImage[i];
            case 7:
                return new StudiableLearnPaywall[i];
            case 8:
                return new StudiableMetadataCategory[i];
            case 9:
                return new StudiableMetadataType[i];
            case 10:
                return new StudiableMeteringData[i];
            case 11:
                return new StudiableQuestionMetadata[i];
            case 12:
                return new StudiableQuestionSource[i];
            case 13:
                return new StudiableRoundProgress[i];
            case 14:
                return new StudiableTaskProgress[i];
            case 15:
                return new StudiableTaskTotalProgress[i];
            case 16:
                return new StudiableText[i];
            case 17:
                return new StudiableTotalProgress[i];
            case 18:
                return new StudiableWriteMasteryBuckets[i];
            case 19:
                return new TrueFalseStudiableQuestion[i];
            case 20:
                return new WrittenStudiableQuestion[i];
            case 21:
                return new FillInTheBlankResponse[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new MatchingGameResponse[i];
            case EventType.AUDIO /* 23 */:
                return new MultipleChoiceResponse[i];
            case EventType.VIDEO /* 24 */:
                return new PLocalGradedAnswerMetadata[i];
            case EventType.SUBS /* 25 */:
                return new PLongtextGradingResult[i];
            case EventType.CDN /* 26 */:
                return new PSmartGradedAnswerMetadata[i];
            case 27:
                return new RevealSelfAssessmentResponse[i];
            case 28:
                return new StudiableQuestionFeedback[i];
            default:
                return new StudiableQuestionGradedAnswer[i];
        }
    }
}
