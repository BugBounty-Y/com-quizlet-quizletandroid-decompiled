package com.google.android.gms.common.api;

import com.google.android.gms.common.Feature;

/* loaded from: classes2.dex */
public final class UnsupportedApiCallException extends UnsupportedOperationException {
    public final Feature a;

    public UnsupportedApiCallException(Feature feature) {
        this.a = feature;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return "Missing ".concat(String.valueOf(this.a));
    }
}
