package com.quizlet.search.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.Y0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchFilterCreatorTypeState extends SearchFilterState<Y0> {

    @NotNull
    public static final Parcelable.Creator<SearchFilterCreatorTypeState> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(19);
    public final Y0 b;

    public SearchFilterCreatorTypeState(Y0 y0) {
        super(Y0.ALL);
        this.b = y0;
    }

    public final Object a() {
        return this.b;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SearchFilterCreatorTypeState) && this.b == ((SearchFilterCreatorTypeState) obj).b;
    }

    public final int hashCode() {
        Y0 y0 = this.b;
        if (y0 == null) {
            return 0;
        }
        return y0.hashCode();
    }

    public final String toString() {
        return "SearchFilterCreatorTypeState(uiFilter=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        Y0 y0 = this.b;
        if (y0 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(y0.name());
        }
    }
}
