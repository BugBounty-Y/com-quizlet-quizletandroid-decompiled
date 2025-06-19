package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class WrittenStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<WrittenStudiableQuestion> CREATOR = new f(20);
    public final QuestionSectionData b;
    public final StudiableQuestionMetadata c;
    public final String d;
    public final StudiableText e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public WrittenStudiableQuestion(QuestionSectionData prompt, StudiableQuestionMetadata metadata, String kmpJson, StudiableText studiableText) {
        super(null);
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        this.b = prompt;
        this.c = metadata;
        this.d = kmpJson;
        this.e = studiableText;
    }

    @Override // com.quizlet.studiablemodels.StudiableQuestion
    public final StudiableQuestionMetadata a() {
        return this.c;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WrittenStudiableQuestion)) {
            return false;
        }
        WrittenStudiableQuestion writtenStudiableQuestion = (WrittenStudiableQuestion) obj;
        return Intrinsics.b(this.b, writtenStudiableQuestion.b) && Intrinsics.b(this.c, writtenStudiableQuestion.c) && Intrinsics.b(this.d, writtenStudiableQuestion.d) && Intrinsics.b(this.e, writtenStudiableQuestion.e);
    }

    public final int hashCode() {
        int iE = d0.e((this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31, this.d);
        StudiableText studiableText = this.e;
        return iE + (studiableText == null ? 0 : studiableText.hashCode());
    }

    public final String toString() {
        return "WrittenStudiableQuestion(prompt=" + this.b + ", metadata=" + this.c + ", kmpJson=" + this.d + ", hint=" + this.e + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelable(this.b, i);
        this.c.writeToParcel(dest, i);
        dest.writeString(this.d);
        StudiableText studiableText = this.e;
        if (studiableText == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableText.writeToParcel(dest, i);
        }
    }
}
