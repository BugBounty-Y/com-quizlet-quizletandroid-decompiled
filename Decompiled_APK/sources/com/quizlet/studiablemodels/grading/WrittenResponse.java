package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class WrittenResponse extends StudiableQuestionResponse {

    @NotNull
    public static final Parcelable.Creator<WrittenResponse> CREATOR = new e(2);
    public final String a;

    public WrittenResponse(String userInput) {
        Intrinsics.checkNotNullParameter(userInput, "userInput");
        this.a = userInput;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof WrittenResponse) && Intrinsics.b(this.a, ((WrittenResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("WrittenResponse(userInput="), this.a, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
    }
}
