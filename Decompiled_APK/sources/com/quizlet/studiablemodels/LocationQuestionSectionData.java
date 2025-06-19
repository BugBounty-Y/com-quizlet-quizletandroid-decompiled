package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class LocationQuestionSectionData extends QuestionSectionData {

    @NotNull
    public static final Parcelable.Creator<LocationQuestionSectionData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(27);
    public final long a;
    public final StudiableDiagramShape b;

    public LocationQuestionSectionData(long j, StudiableDiagramShape shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = j;
        this.b = shape;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LocationQuestionSectionData)) {
            return false;
        }
        LocationQuestionSectionData locationQuestionSectionData = (LocationQuestionSectionData) obj;
        return this.a == locationQuestionSectionData.a && Intrinsics.b(this.b, locationQuestionSectionData.b);
    }

    public final int hashCode() {
        return this.b.a.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "LocationQuestionSectionData(id=" + this.a + ", shape=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        this.b.writeToParcel(dest, i);
    }
}
