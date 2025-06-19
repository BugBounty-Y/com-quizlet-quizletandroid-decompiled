package com.quizlet.remote.model.login;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ResponseData {
    public final EmailData a;

    public ResponseData(@InterfaceC4853h(name = "data") @NotNull EmailData contents) {
        Intrinsics.checkNotNullParameter(contents, "contents");
        this.a = contents;
    }

    @NotNull
    public final ResponseData copy(@InterfaceC4853h(name = "data") @NotNull EmailData contents) {
        Intrinsics.checkNotNullParameter(contents, "contents");
        return new ResponseData(contents);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ResponseData) && Intrinsics.b(this.a, ((ResponseData) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "ResponseData(contents=" + this.a + ")";
    }
}
