package com.google.android.gms.internal.mlkit_vision_barcode;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.v6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3283v6 {
    public static final /* synthetic */ int a = 0;
    public static final /* synthetic */ int b = 0;

    public static int a(int i) {
        if (i == 1) {
            return 0;
        }
        if (i == 2) {
            return 1;
        }
        if (i == 4) {
            return 2;
        }
        if (i == 8) {
            return 3;
        }
        if (i == 16) {
            return 4;
        }
        if (i == 32) {
            return 5;
        }
        if (i == 64) {
            return 6;
        }
        if (i == 128) {
            return 7;
        }
        if (i == 256) {
            return 8;
        }
        if (i == 512) {
            return 9;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "type needs to be >= FIRST and <= LAST, type="));
    }
}
