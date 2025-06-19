package com.quizlet.remote.model.explanations.solution;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSolutionStep {
    public final boolean a;
    public final int b;
    public final List c;

    public RemoteSolutionStep(@InterfaceC4853h(name = "isResult") boolean z, @InterfaceC4853h(name = "stepNumber") int i, @InterfaceC4853h(name = "columns") @NotNull List<RemoteSolutionColumn> columns) {
        Intrinsics.checkNotNullParameter(columns, "columns");
        this.a = z;
        this.b = i;
        this.c = columns;
    }
}
