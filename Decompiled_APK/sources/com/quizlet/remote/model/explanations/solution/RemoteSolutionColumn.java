package com.quizlet.remote.model.explanations.solution;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSolutionColumn {
    public final String a;
    public final boolean b;
    public final RemoteSolutionColumnImages c;

    public RemoteSolutionColumn(@InterfaceC4853h(name = "text") @NotNull String text, @InterfaceC4853h(name = "hasInvalidKatex") boolean z, @InterfaceC4853h(name = "images") @NotNull RemoteSolutionColumnImages images) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(images, "images");
        this.a = text;
        this.b = z;
        this.c = images;
    }
}
