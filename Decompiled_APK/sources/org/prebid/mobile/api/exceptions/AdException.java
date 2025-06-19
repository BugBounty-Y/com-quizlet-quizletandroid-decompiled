package org.prebid.mobile.api.exceptions;

import android.support.v4.media.session.a;

/* loaded from: classes3.dex */
public class AdException extends Exception {
    public final String a;

    public AdException(String str, String str2) {
        this.a = a.l(str, ": ", str2);
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
