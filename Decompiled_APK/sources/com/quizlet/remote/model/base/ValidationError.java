package com.quizlet.remote.model.base;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ValidationError {
    public final String a;
    public final String b;
    public final String c;

    public ValidationError(@InterfaceC4853h(name = "message") @NotNull String serverMessage, @InterfaceC4853h(name = "identifier") @NotNull String identifier, @InterfaceC4853h(name = "field") @NotNull String field) {
        Intrinsics.checkNotNullParameter(serverMessage, "serverMessage");
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        Intrinsics.checkNotNullParameter(field, "field");
        this.a = serverMessage;
        this.b = identifier;
        this.c = field;
    }
}
