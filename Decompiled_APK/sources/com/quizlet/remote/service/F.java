package com.quizlet.remote.service;

import com.quizlet.remote.model.widget.SuggestedSetsResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface F {
    @retrofit2.http.f("widget/suggested-sets")
    Object a(@retrofit2.http.t("numSets") int i, @NotNull kotlin.coroutines.h<? super SuggestedSetsResponse> hVar);
}
