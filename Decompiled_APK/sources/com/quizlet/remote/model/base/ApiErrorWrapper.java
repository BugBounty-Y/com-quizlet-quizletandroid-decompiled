package com.quizlet.remote.model.base;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ApiErrorWrapper {
    public final ApiError a;

    public ApiErrorWrapper(@InterfaceC4853h(name = "error") ApiError apiError) {
        this.a = apiError;
    }

    @NotNull
    public final ApiErrorWrapper copy(@InterfaceC4853h(name = "error") ApiError apiError) {
        return new ApiErrorWrapper(apiError);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ApiErrorWrapper) && Intrinsics.b(this.a, ((ApiErrorWrapper) obj).a);
    }

    public final int hashCode() {
        ApiError apiError = this.a;
        if (apiError == null) {
            return 0;
        }
        return apiError.hashCode();
    }

    public final String toString() {
        return "ApiErrorWrapper(error=" + this.a + ")";
    }
}
