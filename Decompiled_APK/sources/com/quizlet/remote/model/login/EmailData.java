package com.quizlet.remote.model.login;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class EmailData {
    public final ValidateEmail a;

    public EmailData(@InterfaceC4853h(name = "validateEmail") @NotNull ValidateEmail contents) {
        Intrinsics.checkNotNullParameter(contents, "contents");
        this.a = contents;
    }

    @NotNull
    public final EmailData copy(@InterfaceC4853h(name = "validateEmail") @NotNull ValidateEmail contents) {
        Intrinsics.checkNotNullParameter(contents, "contents");
        return new EmailData(contents);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof EmailData) && Intrinsics.b(this.a, ((EmailData) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "EmailData(contents=" + this.a + ")";
    }
}
