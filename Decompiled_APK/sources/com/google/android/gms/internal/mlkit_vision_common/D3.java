package com.google.android.gms.internal.mlkit_vision_common;

/* loaded from: classes2.dex */
public abstract class D3 {
    public static final /* synthetic */ int a = 0;

    public static void a(int i, Object[] objArr) {
        for (int i2 = 0; i2 < i; i2++) {
            if (objArr[i2] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i2, "at index "));
            }
        }
    }
}
