package com.quizlet.remote.model.user;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UserResponseData {
    public final Boolean a;
    public final Integer b;

    public UserResponseData(@InterfaceC4853h(name = "success") Boolean bool, @InterfaceC4853h(name = "status") Integer num) {
        this.a = bool;
        this.b = num;
    }

    @NotNull
    public final UserResponseData copy(@InterfaceC4853h(name = "success") Boolean bool, @InterfaceC4853h(name = "status") Integer num) {
        return new UserResponseData(bool, num);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UserResponseData)) {
            return false;
        }
        UserResponseData userResponseData = (UserResponseData) obj;
        return Intrinsics.b(this.a, userResponseData.a) && Intrinsics.b(this.b, userResponseData.b);
    }

    public final int hashCode() {
        Boolean bool = this.a;
        int iHashCode = (bool == null ? 0 : bool.hashCode()) * 31;
        Integer num = this.b;
        return iHashCode + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        return "UserResponseData(success=" + this.a + ", status=" + this.b + ")";
    }

    public /* synthetic */ UserResponseData(Boolean bool, Integer num, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : bool, (i & 2) != 0 ? null : num);
    }
}
