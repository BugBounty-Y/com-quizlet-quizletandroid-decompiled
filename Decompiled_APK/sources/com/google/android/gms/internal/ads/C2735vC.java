package com.google.android.gms.internal.ads;

import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: com.google.android.gms.internal.ads.vC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2735vC extends AbstractC2457os {
    public final /* synthetic */ int b;
    public final Object c;

    public C2735vC(String str, int i) {
        this.b = i;
        switch (i) {
            case 1:
                this.c = Logger.getLogger(str);
                break;
            default:
                this.c = str;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void i(String str) {
        switch (this.b) {
            case 0:
                new StringBuilder(String.valueOf(str).length() + String.valueOf((String) this.c).length() + 1);
                break;
            default:
                ((Logger) this.c).logp(Level.FINE, "com.googlecode.mp4parser.util.JuliLogger", "logDebug", str);
                break;
        }
    }
}
