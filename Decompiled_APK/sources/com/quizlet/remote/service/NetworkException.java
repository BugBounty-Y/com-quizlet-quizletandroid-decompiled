package com.quizlet.remote.service;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiError;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class NetworkException extends RuntimeException {
    public final ApiError a;
    public final String b;
    public final Throwable c;

    public NetworkException(ApiError apiError, String errorMessage, Throwable error) {
        Intrinsics.checkNotNullParameter(errorMessage, "errorMessage");
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = apiError;
        this.b = errorMessage;
        this.c = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NetworkException)) {
            return false;
        }
        NetworkException networkException = (NetworkException) obj;
        return Intrinsics.b(this.a, networkException.a) && Intrinsics.b(this.b, networkException.b) && Intrinsics.b(this.c, networkException.c);
    }

    public final int hashCode() {
        ApiError apiError = this.a;
        return this.c.hashCode() + d0.e((apiError == null ? 0 : apiError.hashCode()) * 31, 31, this.b);
    }

    @Override // java.lang.Throwable
    public final String toString() {
        return "NetworkException(errorBody=" + this.a + ", errorMessage=" + this.b + ", error=" + this.c + ")";
    }
}
