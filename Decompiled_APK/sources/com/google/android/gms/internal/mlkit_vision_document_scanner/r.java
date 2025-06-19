package com.google.android.gms.internal.mlkit_vision_document_scanner;

/* loaded from: classes2.dex */
public abstract class r {
    public static final /* synthetic */ int a = 0;

    public static int a(int i) {
        if (i == 0) {
            return 0;
        }
        if (i == 90) {
            return 1;
        }
        if (i == 180) {
            return 2;
        }
        if (i == 270) {
            return 3;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Invalid rotation: "));
    }
}
