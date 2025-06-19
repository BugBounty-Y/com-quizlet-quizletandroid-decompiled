package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MultipleChoiceStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<MultipleChoiceStudiableQuestion> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(29);
    public final QuestionSectionData b;
    public final List c;
    public final QuestionSectionData d;
    public final boolean e;
    public final StudiableQuestionMetadata f;
    public final String g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MultipleChoiceStudiableQuestion(QuestionSectionData prompt, List options, QuestionSectionData questionSectionData, boolean z, StudiableQuestionMetadata metadata, String kmpJson) {
        super(null);
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        this.b = prompt;
        this.c = options;
        this.d = questionSectionData;
        this.e = z;
        this.f = metadata;
        this.g = kmpJson;
    }

    @Override // com.quizlet.studiablemodels.StudiableQuestion
    public final StudiableQuestionMetadata a() {
        return this.f;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MultipleChoiceStudiableQuestion)) {
            return false;
        }
        MultipleChoiceStudiableQuestion multipleChoiceStudiableQuestion = (MultipleChoiceStudiableQuestion) obj;
        return Intrinsics.b(this.b, multipleChoiceStudiableQuestion.b) && Intrinsics.b(this.c, multipleChoiceStudiableQuestion.c) && Intrinsics.b(this.d, multipleChoiceStudiableQuestion.d) && this.e == multipleChoiceStudiableQuestion.e && Intrinsics.b(this.f, multipleChoiceStudiableQuestion.f) && Intrinsics.b(this.g, multipleChoiceStudiableQuestion.g);
    }

    public final int hashCode() {
        int iF = d0.f(this.b.hashCode() * 31, 31, this.c);
        QuestionSectionData questionSectionData = this.d;
        return this.g.hashCode() + ((this.f.hashCode() + d0.g((iF + (questionSectionData == null ? 0 : questionSectionData.hashCode())) * 31, 31, this.e)) * 31);
    }

    public final String toString() {
        return "MultipleChoiceStudiableQuestion(prompt=" + this.b + ", options=" + this.c + ", hint=" + this.d + ", hasExactlyOneCorrectAnswer=" + this.e + ", metadata=" + this.f + ", kmpJson=" + this.g + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelable(this.b, i);
        List list = this.c;
        dest.writeInt(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            dest.writeParcelable((Parcelable) it2.next(), i);
        }
        dest.writeParcelable(this.d, i);
        dest.writeInt(this.e ? 1 : 0);
        this.f.writeToParcel(dest, i);
        dest.writeString(this.g);
    }
}
