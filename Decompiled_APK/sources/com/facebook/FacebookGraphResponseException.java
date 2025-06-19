package com.facebook;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class FacebookGraphResponseException extends FacebookException {
    public final w b;

    public FacebookGraphResponseException(w wVar, String str) {
        super(str);
        this.b = wVar;
    }

    @Override // com.facebook.FacebookException, java.lang.Throwable
    public final String toString() {
        w wVar = this.b;
        FacebookRequestError facebookRequestError = wVar != null ? wVar.c : null;
        StringBuilder sb = new StringBuilder("{FacebookGraphResponseException: ");
        String message = getMessage();
        if (message != null) {
            sb.append(message);
            sb.append(" ");
        }
        if (facebookRequestError != null) {
            sb.append("httpResponseCode: ");
            sb.append(facebookRequestError.a);
            sb.append(", facebookErrorCode: ");
            sb.append(facebookRequestError.b);
            sb.append(", facebookErrorType: ");
            sb.append(facebookRequestError.d);
            sb.append(", message: ");
            sb.append(facebookRequestError.a());
            sb.append("}");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "errorStringBuilder.toString()");
        return string;
    }
}
