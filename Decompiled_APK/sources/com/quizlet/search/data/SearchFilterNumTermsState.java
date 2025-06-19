package com.quizlet.search.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.EnumC4484g1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchFilterNumTermsState extends SearchFilterState<EnumC4484g1> {

    @NotNull
    public static final Parcelable.Creator<SearchFilterNumTermsState> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(20);
    public final EnumC4484g1 b;

    public SearchFilterNumTermsState(EnumC4484g1 enumC4484g1) {
        super(EnumC4484g1.ALL);
        this.b = enumC4484g1;
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
        return (obj instanceof SearchFilterNumTermsState) && this.b == ((SearchFilterNumTermsState) obj).b;
    }

    public final int hashCode() {
        EnumC4484g1 enumC4484g1 = this.b;
        if (enumC4484g1 == null) {
            return 0;
        }
        return enumC4484g1.hashCode();
    }

    public final String toString() {
        return "SearchFilterNumTermsState(uiFilter=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        EnumC4484g1 enumC4484g1 = this.b;
        if (enumC4484g1 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(enumC4484g1.name());
        }
    }
}
