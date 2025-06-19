package com.quizlet.remote.model.login;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UsernameCheckResponse extends ApiResponse {
    public final UsernameCheckData d;

    public UsernameCheckResponse(@InterfaceC4853h(name = "data") @NotNull UsernameCheckData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    @NotNull
    public final UsernameCheckResponse copy(@InterfaceC4853h(name = "data") @NotNull UsernameCheckData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new UsernameCheckResponse(data);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UsernameCheckResponse) && Intrinsics.b(this.d, ((UsernameCheckResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "UsernameCheckResponse(data=" + this.d + ")";
    }
}
