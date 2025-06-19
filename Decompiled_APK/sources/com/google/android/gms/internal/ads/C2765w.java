package com.google.android.gms.internal.ads;

import android.hardware.display.DisplayManager;

/* renamed from: com.google.android.gms.internal.ads.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2765w implements DisplayManager.DisplayListener {
    public final DisplayManager a;
    public final /* synthetic */ C2851y b;

    public C2765w(C2851y c2851y, DisplayManager displayManager) {
        this.b = c2851y;
        this.a = displayManager;
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayAdded(int i) {
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayChanged(int i) {
        if (i == 0) {
            C2851y.a(this.b, this.a.getDisplay(0));
        }
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayRemoved(int i) {
    }
}
