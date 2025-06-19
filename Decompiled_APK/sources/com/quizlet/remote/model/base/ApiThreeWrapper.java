package com.quizlet.remote.model.base;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ApiThreeWrapper<T extends ApiResponse> {
    public final List a;
    public final ApiError b;

    public ApiThreeWrapper(List list, ApiError apiError) {
        this.a = list;
        this.b = apiError;
    }

    public final ApiResponse a() {
        List list = this.a;
        if (list != null) {
            return (ApiResponse) CollectionsKt.firstOrNull(list);
        }
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ApiThreeWrapper)) {
            return false;
        }
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
        return Intrinsics.b(this.a, apiThreeWrapper.a) && Intrinsics.b(this.b, apiThreeWrapper.b);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        ApiError apiError = this.b;
        return iHashCode + (apiError != null ? apiError.hashCode() : 0);
    }

    public final String toString() {
        return "ApiThreeWrapper(responses=" + this.a + ", error=" + this.b + ")";
    }

    public /* synthetic */ ApiThreeWrapper(List list, ApiError apiError, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : list, (i & 2) != 0 ? null : apiError);
    }
}
