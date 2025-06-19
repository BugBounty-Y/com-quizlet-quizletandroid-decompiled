package com.quizlet.search.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.EnumC4490i1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchFilterContentTypeState extends SearchFilterState<EnumC4490i1> {

    @NotNull
    public static final Parcelable.Creator<SearchFilterContentTypeState> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(18);
    public final EnumC4490i1 b;

    public SearchFilterContentTypeState(EnumC4490i1 enumC4490i1) {
        super(EnumC4490i1.ALL);
        this.b = enumC4490i1;
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
        return (obj instanceof SearchFilterContentTypeState) && this.b == ((SearchFilterContentTypeState) obj).b;
    }

    public final int hashCode() {
        EnumC4490i1 enumC4490i1 = this.b;
        if (enumC4490i1 == null) {
            return 0;
        }
        return enumC4490i1.hashCode();
    }

    public final String toString() {
        return "SearchFilterContentTypeState(uiFilter=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        EnumC4490i1 enumC4490i1 = this.b;
        if (enumC4490i1 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(enumC4490i1.name());
        }
    }
}
