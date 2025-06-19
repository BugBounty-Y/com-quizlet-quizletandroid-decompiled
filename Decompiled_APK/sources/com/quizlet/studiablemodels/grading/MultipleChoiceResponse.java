package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MultipleChoiceResponse extends StudiableQuestionResponse {

    @NotNull
    public static final Parcelable.Creator<MultipleChoiceResponse> CREATOR = new f(23);
    public final int a;

    public MultipleChoiceResponse(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MultipleChoiceResponse) && this.a == ((MultipleChoiceResponse) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("MultipleChoiceResponse(optionIndex="), this.a, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
    }
}
