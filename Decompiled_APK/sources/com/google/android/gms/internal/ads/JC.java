package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class JC implements HC {
    public static final Object c = new Object();
    public volatile CC a;
    public volatile Object b;

    public static HC a(CC cc) {
        if ((cc instanceof JC) || (cc instanceof BC)) {
            return cc;
        }
        JC jc = new JC();
        jc.b = c;
        jc.a = cc;
        return jc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Object obj = this.b;
        if (obj != c) {
            return obj;
        }
        CC cc = this.a;
        if (cc == null) {
            return this.b;
        }
        Object objZzb = cc.zzb();
        this.b = objZzb;
        this.a = null;
        return objZzb;
    }
}
