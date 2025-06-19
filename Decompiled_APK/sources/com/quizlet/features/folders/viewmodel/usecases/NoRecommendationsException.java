package com.quizlet.features.folders.viewmodel.usecases;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class NoRecommendationsException extends Exception {
    public NoRecommendationsException() {
        super("No recommendations found");
    }
}
