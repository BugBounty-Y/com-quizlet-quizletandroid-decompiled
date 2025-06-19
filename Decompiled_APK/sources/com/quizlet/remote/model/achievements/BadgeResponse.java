package com.quizlet.remote.model.achievements;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class BadgeResponse extends ApiResponse {
    public final BadgeDataResponse d;

    public BadgeResponse(BadgeDataResponse badgeDataResponse) {
        this.d = badgeDataResponse;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BadgeResponse) && Intrinsics.b(this.d, ((BadgeResponse) obj).d);
    }

    public final int hashCode() {
        BadgeDataResponse badgeDataResponse = this.d;
        if (badgeDataResponse == null) {
            return 0;
        }
        return badgeDataResponse.hashCode();
    }

    public final String toString() {
        return "BadgeResponse(data=" + this.d + ")";
    }
}
