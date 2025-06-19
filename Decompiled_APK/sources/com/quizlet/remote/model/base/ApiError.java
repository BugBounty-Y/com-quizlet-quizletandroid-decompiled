package com.quizlet.remote.model.base;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ApiError {
    public final String a;
    public final String b;
    public final Integer c;

    public ApiError(@InterfaceC4853h(name = "message") @NotNull String serverMessage, @InterfaceC4853h(name = "identifier") @NotNull String identifier, @InterfaceC4853h(name = "code") Integer num) {
        Intrinsics.checkNotNullParameter(serverMessage, "serverMessage");
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        this.a = serverMessage;
        this.b = identifier;
        this.c = num;
    }

    @NotNull
    public final ApiError copy(@InterfaceC4853h(name = "message") @NotNull String serverMessage, @InterfaceC4853h(name = "identifier") @NotNull String identifier, @InterfaceC4853h(name = "code") Integer num) {
        Intrinsics.checkNotNullParameter(serverMessage, "serverMessage");
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        return new ApiError(serverMessage, identifier, num);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ApiError)) {
            return false;
        }
        ApiError apiError = (ApiError) obj;
        return Intrinsics.b(this.a, apiError.a) && Intrinsics.b(this.b, apiError.b) && Intrinsics.b(this.c, apiError.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        Integer num = this.c;
        return iE + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return this.c + "(" + this.b + "): " + this.a;
    }
}
