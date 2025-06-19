package com.quizlet.quizletandroid.util;

import java.io.IOException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class QLocalizedException extends Exception {
    public final int a;

    public QLocalizedException(int i, IOException iOException) {
        super(iOException);
        this.a = i;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return "Localized error with StringRes " + this.a;
    }
}
