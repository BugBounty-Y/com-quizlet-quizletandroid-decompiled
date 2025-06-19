package com.quizlet.search.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SearchFiltersStates implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<SearchFiltersStates> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(21);
    public final SearchFilterNumTermsState a;
    public final SearchFilterCreatorTypeState b;
    public final SearchFilterContentTypeState c;

    public SearchFiltersStates(SearchFilterNumTermsState numTermsFilters, SearchFilterCreatorTypeState creatorTypeFilter, SearchFilterContentTypeState contentTypeFilters) {
        Intrinsics.checkNotNullParameter(numTermsFilters, "numTermsFilters");
        Intrinsics.checkNotNullParameter(creatorTypeFilter, "creatorTypeFilter");
        Intrinsics.checkNotNullParameter(contentTypeFilters, "contentTypeFilters");
        this.a = numTermsFilters;
        this.b = creatorTypeFilter;
        this.c = contentTypeFilters;
    }

    public final int a() {
        return (this.c.a() == null ? 0 : 1) + (this.b.a() == null ? 0 : 1) + (this.a.a() == null ? 0 : 1);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchFiltersStates)) {
            return false;
        }
        SearchFiltersStates searchFiltersStates = (SearchFiltersStates) obj;
        return Intrinsics.b(this.a, searchFiltersStates.a) && Intrinsics.b(this.b, searchFiltersStates.b) && Intrinsics.b(this.c, searchFiltersStates.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SearchFiltersStates(numTermsFilters=" + this.a + ", creatorTypeFilter=" + this.b + ", contentTypeFilters=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.a.writeToParcel(dest, i);
        this.b.writeToParcel(dest, i);
        this.c.writeToParcel(dest, i);
    }
}
