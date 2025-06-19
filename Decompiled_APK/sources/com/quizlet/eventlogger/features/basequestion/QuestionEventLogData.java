package com.quizlet.eventlogger.features.basequestion;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableMetadataCategory;
import com.quizlet.studiablemodels.StudiableMetadataType;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestionSource;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.v;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionEventLogData {
    public static final Companion a = new Companion(null);

    @NotNull
    private final QuestionEventSideData answerSideData;
    private final Long id;
    private final long localId;

    @NotNull
    private final QuestionEventSideData promptSideData;

    @NotNull
    private final String questionSource;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static QuestionEventLogData a(StudiableQuestion question) {
            boolean zBooleanValue;
            boolean zBooleanValue2;
            Intrinsics.checkNotNullParameter(question, "question");
            long j = question.a().b;
            Long lValueOf = j < 0 ? null : Long.valueOf(j);
            v vVarB = b(question.b());
            QuestionEventSideData questionEventSideData = new QuestionEventSideData(AbstractC3106b5.g(question.a().c), ((Boolean) vVarB.a).booleanValue(), ((Boolean) vVarB.b).booleanValue(), ((Boolean) vVarB.c).booleanValue());
            boolean zBooleanValue3 = false;
            if (question instanceof MultipleChoiceStudiableQuestion) {
                boolean z = false;
                boolean z2 = false;
                boolean z3 = false;
                for (QuestionSectionData questionSectionData : ((MultipleChoiceStudiableQuestion) question).c) {
                    QuestionEventLogData.a.getClass();
                    v vVarB2 = b(questionSectionData);
                    boolean zBooleanValue4 = ((Boolean) vVarB2.a).booleanValue();
                    boolean zBooleanValue5 = ((Boolean) vVarB2.b).booleanValue();
                    boolean zBooleanValue6 = ((Boolean) vVarB2.c).booleanValue();
                    z = z || zBooleanValue4;
                    z2 = z2 || zBooleanValue5;
                    z3 = z3 || zBooleanValue6;
                }
                zBooleanValue3 = z;
                zBooleanValue2 = z2;
                zBooleanValue = z3;
            } else if (question instanceof RevealSelfAssessmentStudiableQuestion) {
                v vVarB3 = b(((RevealSelfAssessmentStudiableQuestion) question).c);
                zBooleanValue3 = ((Boolean) vVarB3.a).booleanValue();
                zBooleanValue2 = ((Boolean) vVarB3.b).booleanValue();
                zBooleanValue = ((Boolean) vVarB3.c).booleanValue();
            } else if (question instanceof TrueFalseStudiableQuestion) {
                v vVarB4 = b(((TrueFalseStudiableQuestion) question).c);
                zBooleanValue3 = ((Boolean) vVarB4.a).booleanValue();
                zBooleanValue2 = ((Boolean) vVarB4.b).booleanValue();
                zBooleanValue = ((Boolean) vVarB4.c).booleanValue();
            } else {
                if (!(question instanceof FillInTheBlankStudiableQuestion) && !(question instanceof MixedOptionMatchingStudiableQuestion) && !(question instanceof WrittenStudiableQuestion)) {
                    throw new NoWhenBranchMatchedException();
                }
                zBooleanValue = false;
                zBooleanValue2 = false;
            }
            return new QuestionEventLogData(lValueOf, j, questionEventSideData, new QuestionEventSideData(AbstractC3106b5.g(question.a().d), zBooleanValue3, zBooleanValue2, zBooleanValue), c(question.a().f));
        }

        public static v b(QuestionSectionData questionSectionData) {
            if (!(questionSectionData instanceof DefaultQuestionSectionData)) {
                if (!(questionSectionData instanceof LocationQuestionSectionData)) {
                    throw new NoWhenBranchMatchedException();
                }
                Boolean bool = Boolean.FALSE;
                return new v(bool, bool, bool);
            }
            DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
            StudiableText studiableText = defaultQuestionSectionData.a;
            String str = studiableText != null ? studiableText.a : null;
            Boolean boolValueOf = Boolean.valueOf(!(str == null || StringsKt.O(str)));
            StudiableImage studiableImage = defaultQuestionSectionData.b;
            String strA = studiableImage != null ? studiableImage.a() : null;
            Boolean boolValueOf2 = Boolean.valueOf(!(strA == null || StringsKt.O(strA)));
            StudiableAudio studiableAudio = defaultQuestionSectionData.c;
            String str2 = studiableAudio != null ? studiableAudio.a : null;
            return new v(boolValueOf, boolValueOf2, Boolean.valueOf(!(str2 == null || StringsKt.O(str2))));
        }

        public static String c(StudiableQuestionSource studiableQuestionSource) throws JSONException {
            StudiableMetadataCategory studiableMetadataCategory;
            StudiableMetadataType studiableMetadataType;
            JSONObject jSONObject = new JSONObject();
            Integer numValueOf = null;
            jSONObject.put("studiableMetadataType", (studiableQuestionSource == null || (studiableMetadataType = studiableQuestionSource.a) == null) ? null : Integer.valueOf(studiableMetadataType.a));
            jSONObject.put("studiableMetadataRank", studiableQuestionSource != null ? studiableQuestionSource.c : null);
            if (studiableQuestionSource != null && (studiableMetadataCategory = studiableQuestionSource.b) != null) {
                numValueOf = Integer.valueOf(studiableMetadataCategory.a);
            }
            jSONObject.put("studiableMetadataCategory", numValueOf);
            String string = jSONObject.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            return string;
        }

        private Companion() {
        }
    }

    public QuestionEventLogData(Long l, long j, @NotNull QuestionEventSideData promptSideData, @NotNull QuestionEventSideData answerSideData, @NotNull String questionSource) {
        Intrinsics.checkNotNullParameter(promptSideData, "promptSideData");
        Intrinsics.checkNotNullParameter(answerSideData, "answerSideData");
        Intrinsics.checkNotNullParameter(questionSource, "questionSource");
        this.id = l;
        this.localId = j;
        this.promptSideData = promptSideData;
        this.answerSideData = answerSideData;
        this.questionSource = questionSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionEventLogData)) {
            return false;
        }
        QuestionEventLogData questionEventLogData = (QuestionEventLogData) obj;
        return Intrinsics.b(this.id, questionEventLogData.id) && this.localId == questionEventLogData.localId && Intrinsics.b(this.promptSideData, questionEventLogData.promptSideData) && Intrinsics.b(this.answerSideData, questionEventLogData.answerSideData) && Intrinsics.b(this.questionSource, questionEventLogData.questionSource);
    }

    @NotNull
    public final QuestionEventSideData getAnswerSideData() {
        return this.answerSideData;
    }

    public final Long getId() {
        return this.id;
    }

    public final long getLocalId() {
        return this.localId;
    }

    @NotNull
    public final QuestionEventSideData getPromptSideData() {
        return this.promptSideData;
    }

    @NotNull
    public final String getQuestionSource() {
        return this.questionSource;
    }

    public final int hashCode() {
        Long l = this.id;
        return this.questionSource.hashCode() + ((this.answerSideData.hashCode() + ((this.promptSideData.hashCode() + d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.localId)) * 31)) * 31);
    }

    public final String toString() {
        Long l = this.id;
        long j = this.localId;
        QuestionEventSideData questionEventSideData = this.promptSideData;
        QuestionEventSideData questionEventSideData2 = this.answerSideData;
        String str = this.questionSource;
        StringBuilder sb = new StringBuilder("QuestionEventLogData(id=");
        sb.append(l);
        sb.append(", localId=");
        sb.append(j);
        sb.append(", promptSideData=");
        sb.append(questionEventSideData);
        sb.append(", answerSideData=");
        sb.append(questionEventSideData2);
        return AbstractC0147y.g(sb, ", questionSource=", str, ")");
    }

    public /* synthetic */ QuestionEventLogData(Long l, long j, QuestionEventSideData questionEventSideData, QuestionEventSideData questionEventSideData2, String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(l, j, questionEventSideData, questionEventSideData2, (i & 16) != 0 ? "" : str);
    }
}
