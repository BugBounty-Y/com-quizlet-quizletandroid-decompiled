package com.quizlet.login.common.exception;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public class LoginException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public LoginException(String message) {
        super(message);
        Intrinsics.checkNotNullParameter(message, "message");
    }
}
