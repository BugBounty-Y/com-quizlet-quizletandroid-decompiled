package com.quizlet.upgrade.ui.confirmation;

import androidx.lifecycle.X;
import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 {
    public final X b;
    public final boolean c;
    public final boolean d;

    public c(@NotNull m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        this.b = new X(1);
        com.quizlet.features.infra.models.upgrade.a aVar = (com.quizlet.features.infra.models.upgrade.a) savedStateHandle.a("NavigationSource");
        com.quizlet.features.infra.models.upgrade.a.b.getClass();
        this.c = CollectionsKt.F(com.quizlet.features.infra.models.upgrade.a.d, aVar);
        this.d = CollectionsKt.F(com.quizlet.features.infra.models.upgrade.a.c, aVar);
    }
}
