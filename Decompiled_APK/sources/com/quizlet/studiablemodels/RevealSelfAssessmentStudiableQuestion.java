package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RevealSelfAssessmentStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<RevealSelfAssessmentStudiableQuestion> CREATOR = new f(0);
    public final QuestionSectionData b;
    public final QuestionSectionData c;
    public final StudiableQuestionMetadata d;
    public final String e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RevealSelfAssessmentStudiableQuestion(QuestionSectionData front, QuestionSectionData back, StudiableQuestionMetadata metadata, String kmpJson) {
        super(null);
        Intrinsics.checkNotNullParameter(front, "front");
        Intrinsics.checkNotNullParameter(back, "back");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        this.b = front;
        this.c = back;
        this.d = metadata;
        this.e = kmpJson;
    }

    @Override // com.quizlet.studiablemodels.StudiableQuestion
    public final StudiableQuestionMetadata a() {
        return this.d;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RevealSelfAssessmentStudiableQuestion)) {
            return false;
        }
        RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion = (RevealSelfAssessmentStudiableQuestion) obj;
        return Intrinsics.b(this.b, revealSelfAssessmentStudiableQuestion.b) && Intrinsics.b(this.c, revealSelfAssessmentStudiableQuestion.c) && Intrinsics.b(this.d, revealSelfAssessmentStudiableQuestion.d) && Intrinsics.b(this.e, revealSelfAssessmentStudiableQuestion.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "RevealSelfAssessmentStudiableQuestion(front=" + this.b + ", back=" + this.c + ", metadata=" + this.d + ", kmpJson=" + this.e + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelable(this.b, i);
        dest.writeParcelable(this.c, i);
        this.d.writeToParcel(dest, i);
        dest.writeString(this.e);
    }
}
