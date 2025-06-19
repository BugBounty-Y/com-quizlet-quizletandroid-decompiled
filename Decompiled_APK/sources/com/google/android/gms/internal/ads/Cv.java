package com.google.android.gms.internal.ads;

import java.util.Set;

/* loaded from: classes2.dex */
public final class Cv extends AbstractC1981ds {
    @Override // com.google.android.gms.internal.ads.AbstractC1981ds
    public final int a(Av av) {
        int i;
        synchronized (av) {
            i = av.i - 1;
            av.i = i;
        }
        return i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1981ds
    public final void q(Av av, Set set) {
        synchronized (av) {
            try {
                if (av.h == null) {
                    av.h = set;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
