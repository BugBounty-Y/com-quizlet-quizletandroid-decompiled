package com.facebook;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class FacebookDialogException extends FacebookException {
    public final int b;
    public final String c;

    public FacebookDialogException(String str, int i, String str2) {
        super(str);
        this.b = i;
        this.c = str2;
    }

    @Override // com.facebook.FacebookException, java.lang.Throwable
    public final String toString() {
        String str = "{FacebookDialogException: errorCode: " + this.b + ", message: " + getMessage() + ", url: " + this.c + "}";
        Intrinsics.checkNotNullExpressionValue(str, "StringBuilder()\n        …(\"}\")\n        .toString()");
        return str;
    }
}
