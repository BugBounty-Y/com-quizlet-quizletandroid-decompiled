package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.f;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FillInTheBlankResponse extends StudiableQuestionResponse {

    @NotNull
    public static final Parcelable.Creator<FillInTheBlankResponse> CREATOR = new f(21);
    public final List a;

    public FillInTheBlankResponse(List answers) {
        Intrinsics.checkNotNullParameter(answers, "answers");
        this.a = answers;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FillInTheBlankResponse) && Intrinsics.b(this.a, ((FillInTheBlankResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("FillInTheBlankResponse(answers="), this.a);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeStringList(this.a);
    }
}
