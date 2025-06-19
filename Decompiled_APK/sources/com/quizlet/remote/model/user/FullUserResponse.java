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
public final class FullUserResponse extends ApiResponse {
    public final FullUserModels d;

    public FullUserResponse(@InterfaceC4853h(name = "models") FullUserModels fullUserModels) {
        this.d = fullUserModels;
    }

    @NotNull
    public final FullUserResponse copy(@InterfaceC4853h(name = "models") FullUserModels fullUserModels) {
        return new FullUserResponse(fullUserModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FullUserResponse) && Intrinsics.b(this.d, ((FullUserResponse) obj).d);
    }

    public final int hashCode() {
        FullUserModels fullUserModels = this.d;
        if (fullUserModels == null) {
            return 0;
        }
        return fullUserModels.hashCode();
    }

    public final String toString() {
        return "FullUserResponse(models=" + this.d + ")";
    }
}
