package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class E7 extends androidx.browser.customtabs.a {
    public final /* synthetic */ F7 a;

    public E7(F7 f7) {
        this.a = f7;
    }

    @Override // androidx.browser.customtabs.a
    public final void e(int i, Bundle bundle) {
        F7 f7 = this.a;
        f7.getClass();
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.D4)).booleanValue() || f7.d == null) {
            return;
        }
        AbstractC2270kd.a.execute(new androidx.core.provider.a(f7, i, 5));
    }
}
