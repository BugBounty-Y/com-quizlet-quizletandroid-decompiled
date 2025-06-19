package com.quizlet.remote.model.user.delete;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class DeleteUserAccountResponse extends ApiResponse {
    public final Boolean d;

    public /* synthetic */ DeleteUserAccountResponse(Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : bool);
    }

    @NotNull
    public final DeleteUserAccountResponse copy(@InterfaceC4853h(name = "success") Boolean bool) {
        return new DeleteUserAccountResponse(bool);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DeleteUserAccountResponse) && Intrinsics.b(this.d, ((DeleteUserAccountResponse) obj).d);
    }

    public final int hashCode() {
        Boolean bool = this.d;
        if (bool == null) {
            return 0;
        }
        return bool.hashCode();
    }

    public final String toString() {
        return "DeleteUserAccountResponse(success=" + this.d + ")";
    }

    public DeleteUserAccountResponse(@InterfaceC4853h(name = "success") Boolean bool) {
        this.d = bool;
    }
}
