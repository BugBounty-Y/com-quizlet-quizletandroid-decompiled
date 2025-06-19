package com.quizlet.openwrap;

import com.pubmatic.sdk.common.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class OpenWrapException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public OpenWrapException(h exception) {
        super(exception.toString());
        Intrinsics.checkNotNullParameter(exception, "exception");
    }
}
