package com.google.android.gms.internal.ads;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.p9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2475p9 {
    public boolean a = false;
    public boolean b = false;
    public float c = DefinitionKt.NO_Float_VALUE;
    public final AtomicBoolean d = new AtomicBoolean(false);

    public final synchronized boolean a(boolean z) {
        if (!this.d.get()) {
            return z;
        }
        return this.a;
    }
}
