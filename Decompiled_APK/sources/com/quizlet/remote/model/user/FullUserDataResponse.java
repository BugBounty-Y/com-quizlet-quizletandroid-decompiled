package com.quizlet.remote.model.user;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FullUserDataResponse extends ApiResponse {
    public final FullUserModels d;
    public final UserResponseData e;

    public FullUserDataResponse(@InterfaceC4853h(name = "models") FullUserModels fullUserModels, @InterfaceC4853h(name = "data") UserResponseData userResponseData) {
        this.d = fullUserModels;
        this.e = userResponseData;
    }

    @NotNull
    public final FullUserDataResponse copy(@InterfaceC4853h(name = "models") FullUserModels fullUserModels, @InterfaceC4853h(name = "data") UserResponseData userResponseData) {
        return new FullUserDataResponse(fullUserModels, userResponseData);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FullUserDataResponse)) {
            return false;
        }
        FullUserDataResponse fullUserDataResponse = (FullUserDataResponse) obj;
        return Intrinsics.b(this.d, fullUserDataResponse.d) && Intrinsics.b(this.e, fullUserDataResponse.e);
    }

    public final int hashCode() {
        FullUserModels fullUserModels = this.d;
        int iHashCode = (fullUserModels == null ? 0 : fullUserModels.hashCode()) * 31;
        UserResponseData userResponseData = this.e;
        return iHashCode + (userResponseData != null ? userResponseData.hashCode() : 0);
    }

    public final String toString() {
        return "FullUserDataResponse(models=" + this.d + ", data=" + this.e + ")";
    }
}
