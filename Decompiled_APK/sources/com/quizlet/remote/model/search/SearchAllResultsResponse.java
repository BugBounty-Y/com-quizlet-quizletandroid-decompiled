package com.quizlet.remote.model.search;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SearchAllResultsResponse extends ApiResponse {
    public final RemoteAllResultsModels d;
    public final RemoteAllResultsAssociationModels e;
    public final List f;

    public SearchAllResultsResponse(@InterfaceC4853h(name = "models") RemoteAllResultsModels remoteAllResultsModels, @InterfaceC4853h(name = "associations") RemoteAllResultsAssociationModels remoteAllResultsAssociationModels, @InterfaceC4853h(name = "shelfRanking") List<String> list) {
        this.d = remoteAllResultsModels;
        this.e = remoteAllResultsAssociationModels;
        this.f = list;
    }

    @NotNull
    public final SearchAllResultsResponse copy(@InterfaceC4853h(name = "models") RemoteAllResultsModels remoteAllResultsModels, @InterfaceC4853h(name = "associations") RemoteAllResultsAssociationModels remoteAllResultsAssociationModels, @InterfaceC4853h(name = "shelfRanking") List<String> list) {
        return new SearchAllResultsResponse(remoteAllResultsModels, remoteAllResultsAssociationModels, list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SearchAllResultsResponse)) {
            return false;
        }
        SearchAllResultsResponse searchAllResultsResponse = (SearchAllResultsResponse) obj;
        return Intrinsics.b(this.d, searchAllResultsResponse.d) && Intrinsics.b(this.e, searchAllResultsResponse.e) && Intrinsics.b(this.f, searchAllResultsResponse.f);
    }

    public final int hashCode() {
        RemoteAllResultsModels remoteAllResultsModels = this.d;
        int iHashCode = (remoteAllResultsModels == null ? 0 : remoteAllResultsModels.hashCode()) * 31;
        RemoteAllResultsAssociationModels remoteAllResultsAssociationModels = this.e;
        int iHashCode2 = (iHashCode + (remoteAllResultsAssociationModels == null ? 0 : remoteAllResultsAssociationModels.hashCode())) * 31;
        List list = this.f;
        return iHashCode2 + (list != null ? list.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchAllResultsResponse(models=");
        sb.append(this.d);
        sb.append(", associations=");
        sb.append(this.e);
        sb.append(", shelfRanking=");
        return android.support.v4.media.session.a.n(")", sb, this.f);
    }
}
