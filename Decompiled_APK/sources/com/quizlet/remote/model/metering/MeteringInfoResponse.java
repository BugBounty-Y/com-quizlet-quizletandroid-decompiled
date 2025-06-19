package com.quizlet.remote.model.metering;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class MeteringInfoResponse extends ApiResponse {
    public final RemoteMeteringInfo d;
    public final Integer e;

    public MeteringInfoResponse(@InterfaceC4853h(name = "data") RemoteMeteringInfo remoteMeteringInfo, @InterfaceC4853h(name = "reason") Integer num) {
        this.d = remoteMeteringInfo;
        this.e = num;
    }

    @NotNull
    public final MeteringInfoResponse copy(@InterfaceC4853h(name = "data") RemoteMeteringInfo remoteMeteringInfo, @InterfaceC4853h(name = "reason") Integer num) {
        return new MeteringInfoResponse(remoteMeteringInfo, num);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MeteringInfoResponse)) {
            return false;
        }
        MeteringInfoResponse meteringInfoResponse = (MeteringInfoResponse) obj;
        return Intrinsics.b(this.d, meteringInfoResponse.d) && Intrinsics.b(this.e, meteringInfoResponse.e);
    }

    public final int hashCode() {
        RemoteMeteringInfo remoteMeteringInfo = this.d;
        int iHashCode = (remoteMeteringInfo == null ? 0 : remoteMeteringInfo.hashCode()) * 31;
        Integer num = this.e;
        return iHashCode + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        return "MeteringInfoResponse(data=" + this.d + ", reason=" + this.e + ")";
    }
}
