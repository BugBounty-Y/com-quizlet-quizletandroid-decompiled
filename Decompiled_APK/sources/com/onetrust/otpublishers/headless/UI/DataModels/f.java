package com.onetrust.otpublishers.headless.UI.DataModels;

import android.os.Parcel;
import android.os.Parcelable;
import com.comscore.streaming.EventType;
import com.quizlet.eventlogger.model.EditSessionsLog;
import com.quizlet.features.infra.basestudy.data.models.MeteredValue;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.features.infra.models.flashcards.FlashcardSettings$FlashcardSettingsState;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.questionnaire.navigation.Progress;
import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import com.quizlet.generated.enums.O1;
import com.quizlet.generated.enums.Y0;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.login.signup.data.PromptParentEmailData;
import com.quizlet.quizletandroid.sessionhelpers.EditSessionLoggingHelperState;
import com.quizlet.quizletandroid.sessionhelpers.SavedAction;
import com.quizlet.quizletandroid.ui.common.text.URLSpanNoUnderline;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteStudyModeConfig;
import com.quizlet.search.data.SearchFilterContentTypeState;
import com.quizlet.search.data.SearchFilterCreatorTypeState;
import com.quizlet.search.data.SearchFilterNumTermsState;
import com.quizlet.search.data.SearchFiltersStates;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.data.term.TermUiModel;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableDiagramShape;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.StudiableText;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        boolean z;
        boolean z2;
        boolean z3;
        boolean z4;
        boolean z5;
        boolean z6;
        boolean z7;
        boolean z8;
        boolean z9;
        boolean z10;
        boolean z11;
        boolean z12;
        boolean z13;
        boolean z14;
        boolean z15;
        O1 o1;
        switch (this.a) {
            case 0:
                e eVar = new e();
                eVar.b = new ArrayList();
                eVar.a = parcel.readString();
                return eVar;
            case 1:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return MeteredValue.valueOf(parcel.readString());
            case 2:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new StudyEventLogData(parcel.readLong(), parcel.readLong(), parcel.readString(), parcel.readInt() != 0);
            case 3:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                long j = parcel.readLong();
                String string = parcel.readString();
                String string2 = parcel.readString();
                int i = parcel.readInt();
                boolean z16 = false;
                if (parcel.readInt() != 0) {
                    z = false;
                    z16 = true;
                } else {
                    z = false;
                }
                return new Creator(i, j, string, string2, z16, parcel.readInt() == 0 ? z : true);
            case 4:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                String string3 = parcel.readString();
                String string4 = parcel.readString();
                boolean z17 = false;
                boolean z18 = true;
                if (parcel.readInt() != 0) {
                    z2 = false;
                    z17 = true;
                } else {
                    z2 = false;
                }
                if (parcel.readInt() != 0) {
                    z3 = true;
                } else {
                    z3 = true;
                    z18 = z2;
                }
                if (parcel.readInt() != 0) {
                    z4 = z3;
                } else {
                    z4 = z3;
                    z3 = z2;
                }
                if (parcel.readInt() != 0) {
                    z5 = z4;
                } else {
                    z5 = z4;
                    z4 = z2;
                }
                if (parcel.readInt() == 0) {
                    z5 = z2;
                }
                return new FlashcardSettings$FlashcardSettingsState(string3, string4, z17, z18, z3, z4, z5, parcel.readLong(), parcel.readInt());
            case 5:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new AddMaterialFolderData(parcel.readString(), parcel.readLong(), parcel.readInt() != 0);
            case 6:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new MatchSettingsData(parcel.readInt() != 0, parcel.readInt() != 0, parcel.readInt() != 0, parcel.readInt() != 0);
            case 7:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new PracticeTestConfigurationData(parcel.readInt(), parcel.readInt() != 0, parcel.readInt() != 0);
            case 8:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new Progress(parcel.readInt(), parcel.readInt());
            case 9:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                String string5 = parcel.readString();
                int i2 = parcel.readInt();
                LinkedHashMap linkedHashMap = new LinkedHashMap(i2);
                for (int i3 = 0; i3 != i2; i3++) {
                    linkedHashMap.put(parcel.readString(), parcel.readParcelable(QuestionnaireModel.class.getClassLoader()));
                }
                return new QuestionnaireModel(string5, linkedHashMap);
            case 10:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i4 = parcel.readInt();
                LinkedHashMap linkedHashMap2 = new LinkedHashMap(i4);
                for (int i5 = 0; i5 != i4; i5++) {
                    linkedHashMap2.put(parcel.readString(), parcel.readString());
                }
                return new PromptParentEmailData(linkedHashMap2, parcel.readString(), com.quizlet.login.oldlogin.b.valueOf(parcel.readString()));
            case 11:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i6 = parcel.readInt();
                LinkedHashMap linkedHashMap3 = new LinkedHashMap(i6);
                for (int i7 = 0; i7 != i6; i7++) {
                    linkedHashMap3.put(parcel.readString(), parcel.readParcelable(EditSessionLoggingHelperState.class.getClassLoader()));
                }
                int i8 = parcel.readInt();
                ArrayList arrayList = new ArrayList(i8);
                for (int i9 = 0; i9 != i8; i9++) {
                    arrayList.add(parcel.readParcelable(EditSessionLoggingHelperState.class.getClassLoader()));
                }
                return new EditSessionLoggingHelperState(linkedHashMap3, arrayList, (EditSessionsLog) parcel.readParcelable(EditSessionLoggingHelperState.class.getClassLoader()), parcel.readInt() == 0 ? null : com.quizlet.quizletandroid.sessionhelpers.b.valueOf(parcel.readString()), (Date) parcel.readSerializable(), parcel.readInt() != 0 ? SavedAction.CREATOR.createFromParcel(parcel) : null);
            case 12:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new SavedAction(parcel.readString(), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() != 0 ? Long.valueOf(parcel.readLong()) : null);
            case 13:
                URLSpanNoUnderline uRLSpanNoUnderline = new URLSpanNoUnderline(parcel);
                uRLSpanNoUnderline.a = "";
                return uRLSpanNoUnderline;
            case 14:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new LearnSettingsIntentData(parcel.readInt(), parcel.readLong(), (StudyableModelData) parcel.readParcelable(LearnSettingsIntentData.class.getClassLoader()), parcel.readString(), parcel.readString(), parcel.readInt() != 0);
            case 15:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                boolean z19 = false;
                boolean z20 = true;
                if (parcel.readInt() != 0) {
                    z6 = false;
                    z19 = true;
                } else {
                    z6 = false;
                }
                if (parcel.readInt() != 0) {
                    z7 = true;
                } else {
                    z7 = true;
                    z20 = z6;
                }
                if (parcel.readInt() != 0) {
                    z8 = z7;
                } else {
                    z8 = z7;
                    z7 = z6;
                }
                if (parcel.readInt() != 0) {
                    z9 = z8;
                } else {
                    z9 = z8;
                    z8 = z6;
                }
                if (parcel.readInt() != 0) {
                    z10 = z9;
                } else {
                    z10 = z9;
                    z9 = z6;
                }
                if (parcel.readInt() != 0) {
                    z11 = z10;
                } else {
                    z11 = z10;
                    z10 = z6;
                }
                if (parcel.readInt() != 0) {
                    z12 = z11;
                } else {
                    z12 = z11;
                    z11 = z6;
                }
                if (parcel.readInt() != 0) {
                    z13 = z12;
                } else {
                    z13 = z12;
                    z12 = z6;
                }
                if (parcel.readInt() != 0) {
                    z14 = z13;
                } else {
                    z14 = z13;
                    z13 = z6;
                }
                if (parcel.readInt() != 0) {
                    z15 = z14;
                } else {
                    z15 = z14;
                    z14 = z6;
                }
                if (parcel.readInt() == 0) {
                    z15 = z6;
                }
                return new LearnSettingsUpdateData(z19, z20, z7, z8, z9, z10, z11, z12, z13, z14, z15, (WrittenQuestionGradingOption) parcel.readParcelable(LearnSettingsUpdateData.class.getClassLoader()));
            case 16:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new LearnSettingsGradingUpdateData(parcel.readInt() != 0, parcel.readInt() != 0, parcel.readInt() != 0);
            case 17:
                WriteStudyModeConfig writeStudyModeConfig = new WriteStudyModeConfig();
                int i10 = parcel.readInt();
                O1.Companion.getClass();
                O1[] o1ArrValues = O1.values();
                int length = o1ArrValues.length;
                int i11 = 0;
                while (true) {
                    if (i11 < length) {
                        o1 = o1ArrValues[i11];
                        if (o1.a() != i10) {
                            i11++;
                        }
                    } else {
                        o1 = null;
                    }
                }
                writeStudyModeConfig.a = o1;
                writeStudyModeConfig.b = parcel.readByte() > 0;
                writeStudyModeConfig.c = parcel.readByte() > 0;
                writeStudyModeConfig.d = parcel.readByte() > 0;
                writeStudyModeConfig.e = parcel.readByte() > 0;
                return writeStudyModeConfig;
            case 18:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new SearchFilterContentTypeState(parcel.readInt() == 0 ? null : EnumC4490i1.valueOf(parcel.readString()));
            case 19:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new SearchFilterCreatorTypeState(parcel.readInt() == 0 ? null : Y0.valueOf(parcel.readString()));
            case 20:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new SearchFilterNumTermsState(parcel.readInt() == 0 ? null : EnumC4484g1.valueOf(parcel.readString()));
            case 21:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new SearchFiltersStates(SearchFilterNumTermsState.CREATOR.createFromParcel(parcel), SearchFilterCreatorTypeState.CREATOR.createFromParcel(parcel), SearchFilterContentTypeState.CREATOR.createFromParcel(parcel));
            case EventType.WINDOW_STATE /* 22 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new TermSearchUiModel(parcel.readLong(), parcel.readLong(), parcel.readLong(), parcel.readString(), parcel.readInt(), TermUiModel.CREATOR.createFromParcel(parcel));
            case EventType.AUDIO /* 23 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new TermUiModel(parcel.readString(), parcel.readString(), parcel.readString());
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return AssistantCheckpointProgressState.valueOf(parcel.readString());
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new DefaultQuestionSectionData(parcel.readInt() == 0 ? null : StudiableText.CREATOR.createFromParcel(parcel), parcel.readInt() == 0 ? null : StudiableImage.CREATOR.createFromParcel(parcel), parcel.readInt() != 0 ? StudiableAudio.CREATOR.createFromParcel(parcel) : null);
            case EventType.CDN /* 26 */:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                QuestionSectionData questionSectionData = (QuestionSectionData) parcel.readParcelable(FillInTheBlankStudiableQuestion.class.getClassLoader());
                StudiableQuestionMetadata studiableQuestionMetadataCreateFromParcel = StudiableQuestionMetadata.CREATOR.createFromParcel(parcel);
                String string6 = parcel.readString();
                int i12 = parcel.readInt();
                ArrayList arrayList2 = new ArrayList(i12);
                for (int i13 = 0; i13 != i12; i13++) {
                    arrayList2.add(parcel.readParcelable(FillInTheBlankStudiableQuestion.class.getClassLoader()));
                }
                return new FillInTheBlankStudiableQuestion(questionSectionData, studiableQuestionMetadataCreateFromParcel, string6, arrayList2);
            case 27:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new LocationQuestionSectionData(parcel.readLong(), StudiableDiagramShape.CREATOR.createFromParcel(parcel));
            case 28:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i14 = parcel.readInt();
                ArrayList arrayList3 = new ArrayList(i14);
                for (int i15 = 0; i15 != i14; i15++) {
                    arrayList3.add(parcel.readParcelable(MixedOptionMatchingStudiableQuestion.class.getClassLoader()));
                }
                return new MixedOptionMatchingStudiableQuestion(arrayList3, StudiableQuestionMetadata.CREATOR.createFromParcel(parcel), parcel.readString());
            default:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                QuestionSectionData questionSectionData2 = (QuestionSectionData) parcel.readParcelable(MultipleChoiceStudiableQuestion.class.getClassLoader());
                int i16 = parcel.readInt();
                ArrayList arrayList4 = new ArrayList(i16);
                for (int i17 = 0; i17 != i16; i17++) {
                    arrayList4.add(parcel.readParcelable(MultipleChoiceStudiableQuestion.class.getClassLoader()));
                }
                return new MultipleChoiceStudiableQuestion(questionSectionData2, arrayList4, (QuestionSectionData) parcel.readParcelable(MultipleChoiceStudiableQuestion.class.getClassLoader()), parcel.readInt() != 0, StudiableQuestionMetadata.CREATOR.createFromParcel(parcel), parcel.readString());
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new e[i];
            case 1:
                return new MeteredValue[i];
            case 2:
                return new StudyEventLogData[i];
            case 3:
                return new Creator[i];
            case 4:
                return new FlashcardSettings$FlashcardSettingsState[i];
            case 5:
                return new AddMaterialFolderData[i];
            case 6:
                return new MatchSettingsData[i];
            case 7:
                return new PracticeTestConfigurationData[i];
            case 8:
                return new Progress[i];
            case 9:
                return new QuestionnaireModel[i];
            case 10:
                return new PromptParentEmailData[i];
            case 11:
                return new EditSessionLoggingHelperState[i];
            case 12:
                return new SavedAction[i];
            case 13:
                return new URLSpanNoUnderline[i];
            case 14:
                return new LearnSettingsIntentData[i];
            case 15:
                return new LearnSettingsUpdateData[i];
            case 16:
                return new LearnSettingsGradingUpdateData[i];
            case 17:
                return new WriteStudyModeConfig[i];
            case 18:
                return new SearchFilterContentTypeState[i];
            case 19:
                return new SearchFilterCreatorTypeState[i];
            case 20:
                return new SearchFilterNumTermsState[i];
            case 21:
                return new SearchFiltersStates[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new TermSearchUiModel[i];
            case EventType.AUDIO /* 23 */:
                return new TermUiModel[i];
            case EventType.VIDEO /* 24 */:
                return new AssistantCheckpointProgressState[i];
            case EventType.SUBS /* 25 */:
                return new DefaultQuestionSectionData[i];
            case EventType.CDN /* 26 */:
                return new FillInTheBlankStudiableQuestion[i];
            case 27:
                return new LocationQuestionSectionData[i];
            case 28:
                return new MixedOptionMatchingStudiableQuestion[i];
            default:
                return new MultipleChoiceStudiableQuestion[i];
        }
    }
}
