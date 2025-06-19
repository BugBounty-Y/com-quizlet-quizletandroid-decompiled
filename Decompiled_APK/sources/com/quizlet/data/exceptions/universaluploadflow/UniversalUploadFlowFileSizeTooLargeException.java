package com.quizlet.data.exceptions.universaluploadflow;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public class UniversalUploadFlowFileSizeTooLargeException extends Exception {
    public final int a;

    public UniversalUploadFlowFileSizeTooLargeException(int i) {
        super((String) null);
        this.a = i;
    }
}
