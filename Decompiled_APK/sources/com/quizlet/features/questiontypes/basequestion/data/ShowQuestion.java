package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class ShowQuestion implements Parcelable {

    @Metadata
    public static final class FillInTheBlank extends ShowQuestion {

        @NotNull
        public static final Parcelable.Creator<FillInTheBlank> CREATOR = new c();
        public final FillInTheBlankStudiableQuestion a;
        public final long b;
        public final long c;
        public final QuestionSettings d;
        public final A1 e;

        public FillInTheBlank(FillInTheBlankStudiableQuestion studiableQuestion, long j, long j2, QuestionSettings questionSettings, A1 studyModeType) {
            Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
            Intrinsics.checkNotNullParameter(questionSettings, "questionSettings");
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            this.a = studiableQuestion;
            this.b = j;
            this.c = j2;
            this.d = questionSettings;
            this.e = studyModeType;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof FillInTheBlank)) {
                return false;
            }
            FillInTheBlank fillInTheBlank = (FillInTheBlank) obj;
            return Intrinsics.b(this.a, fillInTheBlank.a) && this.b == fillInTheBlank.b && this.c == fillInTheBlank.c && Intrinsics.b(this.d, fillInTheBlank.d) && this.e == fillInTheBlank.e;
        }

        public final int hashCode() {
            return this.e.hashCode() + ((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31);
        }

        public final String toString() {
            return "FillInTheBlank(studiableQuestion=" + this.a + ", sessionId=" + this.b + ", studiableModelId=" + this.c + ", questionSettings=" + this.d + ", studyModeType=" + this.e + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeLong(this.b);
            dest.writeLong(this.c);
            dest.writeParcelable(this.d, i);
            dest.writeString(this.e.name());
        }
    }

    @Metadata
    public static final class MultipleChoice extends ShowQuestion {

        @NotNull
        public static final Parcelable.Creator<MultipleChoice> CREATOR = new d();
        public final MultipleChoiceStudiableQuestion a;
        public final long b;
        public final long c;
        public final QuestionSettings d;
        public final A1 e;
        public final boolean f;
        public final boolean g;
        public final boolean h;

        public MultipleChoice(MultipleChoiceStudiableQuestion studiableQuestion, long j, long j2, QuestionSettings questionSettings, A1 studyModeType, boolean z, boolean z2, boolean z3) {
            Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
            Intrinsics.checkNotNullParameter(questionSettings, "questionSettings");
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            this.a = studiableQuestion;
            this.b = j;
            this.c = j2;
            this.d = questionSettings;
            this.e = studyModeType;
            this.f = z;
            this.g = z2;
            this.h = z3;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof MultipleChoice)) {
                return false;
            }
            MultipleChoice multipleChoice = (MultipleChoice) obj;
            return Intrinsics.b(this.a, multipleChoice.a) && this.b == multipleChoice.b && this.c == multipleChoice.c && Intrinsics.b(this.d, multipleChoice.d) && this.e == multipleChoice.e && this.f == multipleChoice.f && this.g == multipleChoice.g && this.h == multipleChoice.h;
        }

        public final int hashCode() {
            return Boolean.hashCode(this.h) + d0.g(d0.g((this.e.hashCode() + ((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31)) * 31, 31, this.f), 31, this.g);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("MultipleChoice(studiableQuestion=");
            sb.append(this.a);
            sb.append(", sessionId=");
            sb.append(this.b);
            sb.append(", studiableModelId=");
            sb.append(this.c);
            sb.append(", questionSettings=");
            sb.append(this.d);
            sb.append(", studyModeType=");
            sb.append(this.e);
            sb.append(", shouldShowFeedback=");
            sb.append(this.f);
            sb.append(", hasDiagramAnswers=");
            sb.append(this.g);
            sb.append(", didMissQuestionRecently=");
            return android.support.v4.media.session.a.o(")", sb, this.h);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeLong(this.b);
            dest.writeLong(this.c);
            dest.writeParcelable(this.d, i);
            dest.writeString(this.e.name());
            dest.writeInt(this.f ? 1 : 0);
            dest.writeInt(this.g ? 1 : 0);
            dest.writeInt(this.h ? 1 : 0);
        }
    }

    @Metadata
    public static final class None extends ShowQuestion {
        public static final None a = new None();

        @NotNull
        public static final Parcelable.Creator<None> CREATOR = new e();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class SelfAssessment extends ShowQuestion {

        @NotNull
        public static final Parcelable.Creator<SelfAssessment> CREATOR = new f();
        public final RevealSelfAssessmentStudiableQuestion a;
        public final long b;
        public final long c;
        public final QuestionSettings d;
        public final A1 e;

        public SelfAssessment(RevealSelfAssessmentStudiableQuestion studiableQuestion, long j, long j2, QuestionSettings questionSettings, A1 studyModeType) {
            Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
            Intrinsics.checkNotNullParameter(questionSettings, "questionSettings");
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            this.a = studiableQuestion;
            this.b = j;
            this.c = j2;
            this.d = questionSettings;
            this.e = studyModeType;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SelfAssessment)) {
                return false;
            }
            SelfAssessment selfAssessment = (SelfAssessment) obj;
            return Intrinsics.b(this.a, selfAssessment.a) && this.b == selfAssessment.b && this.c == selfAssessment.c && Intrinsics.b(this.d, selfAssessment.d) && this.e == selfAssessment.e;
        }

        public final int hashCode() {
            return this.e.hashCode() + ((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31);
        }

        public final String toString() {
            return "SelfAssessment(studiableQuestion=" + this.a + ", sessionId=" + this.b + ", studiableModelId=" + this.c + ", questionSettings=" + this.d + ", studyModeType=" + this.e + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeLong(this.b);
            dest.writeLong(this.c);
            dest.writeParcelable(this.d, i);
            dest.writeString(this.e.name());
        }
    }

    @Metadata
    public static final class TrueFalse extends ShowQuestion {

        @NotNull
        public static final Parcelable.Creator<TrueFalse> CREATOR = new g();
        public final TrueFalseStudiableQuestion a;
        public final long b;
        public final long c;
        public final QuestionSettings d;
        public final A1 e;
        public final boolean f;

        public TrueFalse(TrueFalseStudiableQuestion studiableQuestion, long j, long j2, QuestionSettings questionSettings, A1 studyModeType, boolean z) {
            Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
            Intrinsics.checkNotNullParameter(questionSettings, "questionSettings");
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            this.a = studiableQuestion;
            this.b = j;
            this.c = j2;
            this.d = questionSettings;
            this.e = studyModeType;
            this.f = z;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof TrueFalse)) {
                return false;
            }
            TrueFalse trueFalse = (TrueFalse) obj;
            return Intrinsics.b(this.a, trueFalse.a) && this.b == trueFalse.b && this.c == trueFalse.c && Intrinsics.b(this.d, trueFalse.d) && this.e == trueFalse.e && this.f == trueFalse.f;
        }

        public final int hashCode() {
            return Boolean.hashCode(this.f) + ((this.e.hashCode() + ((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31)) * 31);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("TrueFalse(studiableQuestion=");
            sb.append(this.a);
            sb.append(", sessionId=");
            sb.append(this.b);
            sb.append(", studiableModelId=");
            sb.append(this.c);
            sb.append(", questionSettings=");
            sb.append(this.d);
            sb.append(", studyModeType=");
            sb.append(this.e);
            sb.append(", shouldShowFeedback=");
            return android.support.v4.media.session.a.o(")", sb, this.f);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeLong(this.b);
            dest.writeLong(this.c);
            dest.writeParcelable(this.d, i);
            dest.writeString(this.e.name());
            dest.writeInt(this.f ? 1 : 0);
        }
    }

    @Metadata
    public static final class Written extends ShowQuestion {

        @NotNull
        public static final Parcelable.Creator<Written> CREATOR = new h();
        public final WrittenStudiableQuestion a;
        public final long b;
        public final long c;
        public final QuestionSettings d;
        public final A1 e;
        public final boolean f;
        public final InterfaceC4176w0 g;
        public final boolean h;

        public Written(WrittenStudiableQuestion studiableQuestion, long j, long j2, QuestionSettings questionSettings, A1 studyModeType, boolean z, InterfaceC4176w0 interfaceC4176w0, boolean z2) {
            Intrinsics.checkNotNullParameter(studiableQuestion, "studiableQuestion");
            Intrinsics.checkNotNullParameter(questionSettings, "questionSettings");
            Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
            this.a = studiableQuestion;
            this.b = j;
            this.c = j2;
            this.d = questionSettings;
            this.e = studyModeType;
            this.f = z;
            this.g = interfaceC4176w0;
            this.h = z2;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Written)) {
                return false;
            }
            Written written = (Written) obj;
            return Intrinsics.b(this.a, written.a) && this.b == written.b && this.c == written.c && Intrinsics.b(this.d, written.d) && this.e == written.e && this.f == written.f && Intrinsics.b(this.g, written.g) && this.h == written.h;
        }

        public final int hashCode() {
            int iG = d0.g((this.e.hashCode() + ((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31)) * 31, 31, this.f);
            InterfaceC4176w0 interfaceC4176w0 = this.g;
            return Boolean.hashCode(this.h) + ((iG + (interfaceC4176w0 == null ? 0 : interfaceC4176w0.hashCode())) * 31);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Written(studiableQuestion=");
            sb.append(this.a);
            sb.append(", sessionId=");
            sb.append(this.b);
            sb.append(", studiableModelId=");
            sb.append(this.c);
            sb.append(", questionSettings=");
            sb.append(this.d);
            sb.append(", studyModeType=");
            sb.append(this.e);
            sb.append(", shouldShowFeedback=");
            sb.append(this.f);
            sb.append(", meteredEvent=");
            sb.append(this.g);
            sb.append(", didMissQuestionRecently=");
            return android.support.v4.media.session.a.o(")", sb, this.h);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeLong(this.b);
            dest.writeLong(this.c);
            dest.writeParcelable(this.d, i);
            dest.writeString(this.e.name());
            dest.writeInt(this.f ? 1 : 0);
            dest.writeSerializable(this.g);
            dest.writeInt(this.h ? 1 : 0);
        }
    }
}
