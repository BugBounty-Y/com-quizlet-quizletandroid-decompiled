package com.quizlet.remote.model.login;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UsernameCheckData {
    public final UsernameCheck a;

    public UsernameCheckData(@InterfaceC4853h(name = "checkUsername") @NotNull UsernameCheck checkUsername) {
        Intrinsics.checkNotNullParameter(checkUsername, "checkUsername");
        this.a = checkUsername;
    }

    @NotNull
    public final UsernameCheckData copy(@InterfaceC4853h(name = "checkUsername") @NotNull UsernameCheck checkUsername) {
        Intrinsics.checkNotNullParameter(checkUsername, "checkUsername");
        return new UsernameCheckData(checkUsername);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof UsernameCheckData) && Intrinsics.b(this.a, ((UsernameCheckData) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UsernameCheckData(checkUsername=" + this.a + ")";
    }
}
