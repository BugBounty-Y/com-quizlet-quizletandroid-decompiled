package com.google.android.gms.internal.ads;

import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.ho, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2153ho implements CC {
    public final /* synthetic */ int a = 1;
    public HC b;

    public /* synthetic */ C2153ho() {
    }

    public static void a(C2153ho c2153ho, HC hc) {
        if (c2153ho.b != null) {
            throw new IllegalStateException();
        }
        c2153ho.b = hc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Un((Set) this.b.zzb(), 1);
            default:
                HC hc = this.b;
                if (hc != null) {
                    return hc.zzb();
                }
                throw new IllegalStateException();
        }
    }

    public C2153ho(HC hc) {
        this.b = hc;
    }
}
