package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TrueFalseStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<TrueFalseStudiableQuestion> CREATOR = new f(19);
    public final QuestionSectionData b;
    public final QuestionSectionData c;
    public final StudiableQuestionMetadata d;
    public final String e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public TrueFalseStudiableQuestion(QuestionSectionData prompt, QuestionSectionData goesWith, StudiableQuestionMetadata metadata, String kmpJson) {
        super(null);
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(goesWith, "goesWith");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        this.b = prompt;
        this.c = goesWith;
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
        if (!(obj instanceof TrueFalseStudiableQuestion)) {
            return false;
        }
        TrueFalseStudiableQuestion trueFalseStudiableQuestion = (TrueFalseStudiableQuestion) obj;
        return Intrinsics.b(this.b, trueFalseStudiableQuestion.b) && Intrinsics.b(this.c, trueFalseStudiableQuestion.c) && Intrinsics.b(this.d, trueFalseStudiableQuestion.d) && Intrinsics.b(this.e, trueFalseStudiableQuestion.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "TrueFalseStudiableQuestion(prompt=" + this.b + ", goesWith=" + this.c + ", metadata=" + this.d + ", kmpJson=" + this.e + ")";
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
