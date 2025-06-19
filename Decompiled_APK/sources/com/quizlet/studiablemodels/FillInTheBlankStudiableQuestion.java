package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FillInTheBlankStudiableQuestion extends StudiableQuestion {

    @NotNull
    public static final Parcelable.Creator<FillInTheBlankStudiableQuestion> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(26);
    public final QuestionSectionData b;
    public final StudiableQuestionMetadata c;
    public final String d;
    public final ArrayList e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FillInTheBlankStudiableQuestion(QuestionSectionData prompt, StudiableQuestionMetadata metadata, String kmpJson, ArrayList segments) {
        super(null);
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(kmpJson, "kmpJson");
        Intrinsics.checkNotNullParameter(segments, "segments");
        this.b = prompt;
        this.c = metadata;
        this.d = kmpJson;
        this.e = segments;
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
        if (!(obj instanceof FillInTheBlankStudiableQuestion)) {
            return false;
        }
        FillInTheBlankStudiableQuestion fillInTheBlankStudiableQuestion = (FillInTheBlankStudiableQuestion) obj;
        return Intrinsics.b(this.b, fillInTheBlankStudiableQuestion.b) && Intrinsics.b(this.c, fillInTheBlankStudiableQuestion.c) && Intrinsics.b(this.d, fillInTheBlankStudiableQuestion.d) && this.e.equals(fillInTheBlankStudiableQuestion.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e((this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FillInTheBlankStudiableQuestion(prompt=");
        sb.append(this.b);
        sb.append(", metadata=");
        sb.append(this.c);
        sb.append(", kmpJson=");
        sb.append(this.d);
        sb.append(", segments=");
        return AbstractC0147y.f(")", sb, this.e);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeParcelable(this.b, i);
        this.c.writeToParcel(dest, i);
        dest.writeString(this.d);
        ArrayList arrayList = this.e;
        dest.writeInt(arrayList.size());
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            dest.writeParcelable((Parcelable) it2.next(), i);
        }
    }
}
