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
public final class UserResponse extends ApiResponse {
    public final UserModels d;

    public UserResponse(@InterfaceC4853h(name = "models") UserModels userModels) {
        this.d = userModels;
    }

    @NotNull
    public final UserResponse copy(@InterfaceC4853h(name = "models") UserModels userModels) {
        return new UserResponse(userModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UserResponse) && Intrinsics.b(this.d, ((UserResponse) obj).d);
    }

    public final int hashCode() {
        UserModels userModels = this.d;
        if (userModels == null) {
            return 0;
        }
        return userModels.hashCode();
    }

    public final String toString() {
        return "UserResponse(models=" + this.d + ")";
    }
}
