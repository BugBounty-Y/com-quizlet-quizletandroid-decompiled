package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;

/* renamed from: com.google.android.gms.internal.ads.vx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2762vx extends androidx.appcompat.app.y {
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2762vx(int i, byte[] bArr) {
        super(bArr);
        this.d = i;
    }

    @Override // androidx.appcompat.app.y
    public final AbstractC1047f0 q(int i, byte[] bArr) {
        switch (this.d) {
            case 0:
                return new C2719ux(i, bArr, 0);
            default:
                return new C2719ux(i, bArr, 1);
        }
    }
}
