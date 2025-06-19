package com.google.android.gms.common.api;

import com.google.android.gms.common.api.internal.BasePendingResult;

/* loaded from: classes2.dex */
public final class l extends BasePendingResult {
    public final Status a;

    public l(Status status) {
        super(null);
        this.a = status;
    }

    @Override // com.google.android.gms.common.api.internal.BasePendingResult
    public final k c(Status status) {
        return this.a;
    }
}
