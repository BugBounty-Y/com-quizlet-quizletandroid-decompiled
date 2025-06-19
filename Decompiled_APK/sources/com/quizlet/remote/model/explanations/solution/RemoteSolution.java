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
public final class RemoteSolution {
    public final List a;
    public final int b;

    public RemoteSolution(@InterfaceC4853h(name = "steps") @NotNull List<RemoteSolutionStep> steps, @InterfaceC4853h(name = "totalSteps") int i) {
        Intrinsics.checkNotNullParameter(steps, "steps");
        this.a = steps;
        this.b = i;
    }
}
