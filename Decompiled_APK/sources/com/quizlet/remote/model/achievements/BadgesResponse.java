package com.quizlet.remote.model.achievements;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class BadgesResponse extends ApiResponse {
    public final List d;

    public BadgesResponse(List data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BadgesResponse) && Intrinsics.b(this.d, ((BadgesResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("BadgesResponse(data="), this.d);
    }
}
