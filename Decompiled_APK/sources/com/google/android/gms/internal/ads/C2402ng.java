package com.google.android.gms.internal.ads;

import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.ng, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2402ng implements InterfaceC2488pg {
    public final Map a;

    public C2402ng(Map map) {
        this.a = map;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2488pg
    public final InterfaceC2751vm a(int i, String str) {
        return (InterfaceC2751vm) this.a.get(str);
    }
}
