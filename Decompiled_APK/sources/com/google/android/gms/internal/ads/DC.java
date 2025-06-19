package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class DC implements CC, InterfaceC2907zC {
    public static final DC b = new DC(null);
    public final Object a;

    public DC(Object obj) {
        this.a = obj;
    }

    public static DC a(Object obj) {
        AbstractC1981ds.g(obj, "instance cannot be null");
        return new DC(obj);
    }

    public static DC b(Object obj) {
        return obj == null ? b : new DC(obj);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        return this.a;
    }
}
