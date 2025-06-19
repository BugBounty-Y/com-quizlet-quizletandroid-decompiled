package com.quizlet.remote.model.search;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SearchMisspellingsResponse extends ApiResponse {
    public final String d;
    public final String e;
    public final Boolean f;
    public final String g;

    public /* synthetic */ SearchMisspellingsResponse(String str, String str2, Boolean bool, String str3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? Boolean.FALSE : bool, (i & 8) != 0 ? null : str3);
    }

    @NotNull
    public final SearchMisspellingsResponse copy(@InterfaceC4853h(name = "originalQuery") String str, @InterfaceC4853h(name = "correctedQuery") String str2, @InterfaceC4853h(name = "isQueryCorrected") Boolean bool, @InterfaceC4853h(name = "misspellingsMessage") String str3) {
        return new SearchMisspellingsResponse(str, str2, bool, str3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchMisspellingsResponse)) {
            return false;
        }
        SearchMisspellingsResponse searchMisspellingsResponse = (SearchMisspellingsResponse) obj;
        return Intrinsics.b(this.d, searchMisspellingsResponse.d) && Intrinsics.b(this.e, searchMisspellingsResponse.e) && Intrinsics.b(this.f, searchMisspellingsResponse.f) && Intrinsics.b(this.g, searchMisspellingsResponse.g);
    }

    public final int hashCode() {
        String str = this.d;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.e;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Boolean bool = this.f;
        int iHashCode3 = (iHashCode2 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str3 = this.g;
        return iHashCode3 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchMisspellingsResponse(originalQuery=");
        sb.append(this.d);
        sb.append(", correctedQuery=");
        sb.append(this.e);
        sb.append(", isQueryCorrected=");
        sb.append(this.f);
        sb.append(", misspellingsMessage=");
        return android.support.v4.media.session.a.t(sb, this.g, ")");
    }

    public SearchMisspellingsResponse(@InterfaceC4853h(name = "originalQuery") String str, @InterfaceC4853h(name = "correctedQuery") String str2, @InterfaceC4853h(name = "isQueryCorrected") Boolean bool, @InterfaceC4853h(name = "misspellingsMessage") String str3) {
        this.d = str;
        this.e = str2;
        this.f = bool;
        this.g = str3;
    }
}
