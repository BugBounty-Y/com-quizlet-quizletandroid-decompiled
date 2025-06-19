package com.quizlet.api.util;

import android.content.Context;
import com.quizlet.api.model.ServerProvidedError;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ApiErrorResolverWrapper {

    @NotNull
    private final Context context;

    public ApiErrorResolverWrapper(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String a(ServerProvidedError error) {
        Intrinsics.checkNotNullParameter(error, "error");
        return ApiErrorResolver.a(this.context, error);
    }
}
