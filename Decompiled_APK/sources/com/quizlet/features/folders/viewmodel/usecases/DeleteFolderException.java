package com.quizlet.features.folders.viewmodel.usecases;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class DeleteFolderException extends Exception {
    public DeleteFolderException() {
        super("Failed to delete folder");
    }
}
