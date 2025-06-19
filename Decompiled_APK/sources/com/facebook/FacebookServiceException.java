package com.facebook;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class FacebookServiceException extends FacebookException {
    public final FacebookRequestError b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FacebookServiceException(FacebookRequestError requestError, String str) {
        super(str);
        Intrinsics.checkNotNullParameter(requestError, "requestError");
        this.b = requestError;
    }

    @Override // com.facebook.FacebookException, java.lang.Throwable
    public final String toString() {
        StringBuilder sb = new StringBuilder("{FacebookServiceException: httpResponseCode: ");
        FacebookRequestError facebookRequestError = this.b;
        sb.append(facebookRequestError.a);
        sb.append(", facebookErrorCode: ");
        sb.append(facebookRequestError.b);
        sb.append(", facebookErrorType: ");
        sb.append(facebookRequestError.d);
        sb.append(", message: ");
        sb.append(facebookRequestError.a());
        sb.append("}");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder()\n        …(\"}\")\n        .toString()");
        return string;
    }
}
