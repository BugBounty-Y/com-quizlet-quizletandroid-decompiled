package com.google.android.gms.internal.measurement;

import android.database.ContentObserver;

/* renamed from: com.google.android.gms.internal.measurement.x1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3078x1 extends ContentObserver {
    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        F1.i.incrementAndGet();
    }
}
