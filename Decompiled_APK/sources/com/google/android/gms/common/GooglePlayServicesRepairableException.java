package com.google.android.gms.common;

/* loaded from: classes2.dex */
public class GooglePlayServicesRepairableException extends UserRecoverableException {
    public final int a;

    public GooglePlayServicesRepairableException(int i) {
        super("Google Play Services not available");
        this.a = i;
    }
}
