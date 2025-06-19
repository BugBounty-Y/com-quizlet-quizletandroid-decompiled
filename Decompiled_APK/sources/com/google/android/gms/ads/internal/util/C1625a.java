package com.google.android.gms.ads.internal.util;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.ads.internal.util.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1625a {
    public boolean a;
    public float b;

    public final synchronized float a() {
        synchronized (this) {
            float f = this.b;
            if (f >= DefinitionKt.NO_Float_VALUE) {
                return f;
            }
            return 1.0f;
        }
    }
}
