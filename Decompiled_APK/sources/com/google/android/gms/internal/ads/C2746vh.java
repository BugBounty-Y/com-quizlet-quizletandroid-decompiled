package com.google.android.gms.internal.ads;

import android.os.Bundle;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.vh, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2746vh extends AbstractC2863yB implements InterfaceC1999e9 {
    public final Bundle c;

    public C2746vh(Set set) {
        super(set);
        this.c = new Bundle();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1999e9
    public final synchronized void v(Bundle bundle, String str) {
        this.c.putAll(bundle);
        j1(new C1927ch(9));
    }
}
