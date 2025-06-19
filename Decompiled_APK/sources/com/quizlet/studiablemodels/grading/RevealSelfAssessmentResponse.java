package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RevealSelfAssessmentResponse extends StudiableQuestionResponse {

    @NotNull
    public static final Parcelable.Creator<RevealSelfAssessmentResponse> CREATOR = new f(27);
    public final a a;

    public RevealSelfAssessmentResponse(a option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RevealSelfAssessmentResponse) && this.a == ((RevealSelfAssessmentResponse) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RevealSelfAssessmentResponse(option=" + this.a + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a.name());
    }
}
