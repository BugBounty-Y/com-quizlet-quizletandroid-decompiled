package com.quizlet.data.exceptions.folder;

import androidx.compose.animation.d0;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class FolderDoesNotExistException extends Exception {
    public FolderDoesNotExistException(long j) {
        super(d0.o(j, "Folder with ID ", " does not exist"));
    }
}
