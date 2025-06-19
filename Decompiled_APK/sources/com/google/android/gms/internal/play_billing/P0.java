package com.google.android.gms.internal.play_billing;

import java.io.IOException;

/* loaded from: classes2.dex */
public abstract class P0 {
    protected int zza;

    public abstract int a(InterfaceC3852y1 interfaceC3852y1);

    public final byte[] b() {
        try {
            AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) this;
            int iE = abstractC3787c1.e();
            byte[] bArr = new byte[iE];
            V0 v0 = new V0(iE, bArr);
            InterfaceC3852y1 interfaceC3852y1A = C3843v1.c.a(abstractC3787c1.getClass());
            C3817m1 c3817m1 = v0.b;
            if (c3817m1 == null) {
                c3817m1 = new C3817m1(v0);
            }
            interfaceC3852y1A.h(abstractC3787c1, c3817m1);
            if (iE - v0.e == 0) {
                return bArr;
            }
            throw new IllegalStateException("Did not write as much data as expected.");
        } catch (IOException e) {
            throw new RuntimeException(android.support.v4.media.session.a.B("Serializing ", getClass().getName(), " to a byte array threw an IOException (should never happen)."), e);
        }
    }
}
