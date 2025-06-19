package com.quizlet.features.folders.viewmodel.usecases;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class HiddenFolderException extends Exception {
    public HiddenFolderException() {
        super("Folder is hidden, permission not allowed");
    }
}
