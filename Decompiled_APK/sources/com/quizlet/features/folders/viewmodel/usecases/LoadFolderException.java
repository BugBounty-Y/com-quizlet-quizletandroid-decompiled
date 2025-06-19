package com.quizlet.features.folders.viewmodel.usecases;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LoadFolderException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public LoadFolderException(Throwable e) {
        super("Failed to load folder", e);
        Intrinsics.checkNotNullParameter(e, "e");
    }
}
