package com.quizlet.remote.model.login;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UsernameCheck {
    public final boolean a;
    public final List b;

    public UsernameCheck(@InterfaceC4853h(name = "success") boolean z, @InterfaceC4853h(name = "suggestions") List<String> list) {
        this.a = z;
        this.b = list;
    }

    @NotNull
    public final UsernameCheck copy(@InterfaceC4853h(name = "success") boolean z, @InterfaceC4853h(name = "suggestions") List<String> list) {
        return new UsernameCheck(z, list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UsernameCheck)) {
            return false;
        }
        UsernameCheck usernameCheck = (UsernameCheck) obj;
        return this.a == usernameCheck.a && Intrinsics.b(this.b, usernameCheck.b);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        List list = this.b;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        return "UsernameCheck(success=" + this.a + ", suggestions=" + this.b + ")";
    }
}
