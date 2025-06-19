package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MatchingGameResponse extends StudiableQuestionResponse {

    @NotNull
    public static final Parcelable.Creator<MatchingGameResponse> CREATOR = new f(22);
    public final int a;
    public final int b;

    public MatchingGameResponse(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MatchingGameResponse)) {
            return false;
        }
        MatchingGameResponse matchingGameResponse = (MatchingGameResponse) obj;
        return this.a == matchingGameResponse.a && this.b == matchingGameResponse.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MatchingGameResponse(firstIndex=");
        sb.append(this.a);
        sb.append(", secondIndex=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        dest.writeInt(this.b);
    }
}
