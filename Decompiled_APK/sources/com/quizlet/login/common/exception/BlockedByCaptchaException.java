package com.quizlet.login.common.exception;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class BlockedByCaptchaException extends LoginException {
    public BlockedByCaptchaException() {
        this(0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BlockedByCaptchaException(int i) {
        super("Log-in blocked by CAPTCHA. Showing CAPTCHA toast.");
        Intrinsics.checkNotNullParameter("Log-in blocked by CAPTCHA. Showing CAPTCHA toast.", "message");
    }
}
