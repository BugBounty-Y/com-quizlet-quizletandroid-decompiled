package com.google.mlkit.common;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public class MlKitException extends Exception {
    public final int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MlKitException(String str, int i) {
        super(str);
        u.f(str, "Provided message must not be empty.");
        this.a = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MlKitException(String str, Exception exc) {
        super(str, exc);
        u.f(str, "Provided message must not be empty.");
        this.a = 13;
    }
}
