package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableQuestionGradedAnswer implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableQuestionGradedAnswer> CREATOR = new f(29);
    public final boolean a;
    public final StudiableQuestionFeedback b;
    public final Boolean c;
    public final Boolean d;
    public final boolean e;
    public final PGradedAnswerMetadata f;

    public StudiableQuestionGradedAnswer(boolean z, StudiableQuestionFeedback feedback, Boolean bool, Boolean bool2, boolean z2, PGradedAnswerMetadata gradedAnswerMetaData) {
        Intrinsics.checkNotNullParameter(feedback, "feedback");
        Intrinsics.checkNotNullParameter(gradedAnswerMetaData, "gradedAnswerMetaData");
        this.a = z;
        this.b = feedback;
        this.c = bool;
        this.d = bool2;
        this.e = z2;
        this.f = gradedAnswerMetaData;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableQuestionGradedAnswer)) {
            return false;
        }
        StudiableQuestionGradedAnswer studiableQuestionGradedAnswer = (StudiableQuestionGradedAnswer) obj;
        return this.a == studiableQuestionGradedAnswer.a && Intrinsics.b(this.b, studiableQuestionGradedAnswer.b) && Intrinsics.b(this.c, studiableQuestionGradedAnswer.c) && Intrinsics.b(this.d, studiableQuestionGradedAnswer.d) && this.e == studiableQuestionGradedAnswer.e && Intrinsics.b(this.f, studiableQuestionGradedAnswer.f);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31;
        Boolean bool = this.c;
        int iHashCode2 = (iHashCode + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.d;
        return this.f.hashCode() + d0.g((iHashCode2 + (bool2 != null ? bool2.hashCode() : 0)) * 31, 31, this.e);
    }

    public final String toString() {
        return "StudiableQuestionGradedAnswer(isCorrect=" + this.a + ", feedback=" + this.b + ", suggestPartialAnswerOption=" + this.c + ", levenshteinPlus=" + this.d + ", isSmartGradingUsed=" + this.e + ", gradedAnswerMetaData=" + this.f + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a ? 1 : 0);
        this.b.writeToParcel(dest, i);
        Boolean bool = this.c;
        if (bool == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(bool.booleanValue() ? 1 : 0);
        }
        Boolean bool2 = this.d;
        if (bool2 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(bool2.booleanValue() ? 1 : 0);
        }
        dest.writeInt(this.e ? 1 : 0);
        dest.writeParcelable(this.f, i);
    }
}
