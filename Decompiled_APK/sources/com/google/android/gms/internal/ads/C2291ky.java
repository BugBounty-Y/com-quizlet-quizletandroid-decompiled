package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.ky, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2291ky {
    public final HashMap a;
    public final HashMap b;

    public /* synthetic */ C2291ky(Ps ps) {
        this.a = new HashMap((HashMap) ps.a);
        this.b = new HashMap((HashMap) ps.b);
    }

    public final Object a(AbstractC2025es abstractC2025es, Class cls) throws GeneralSecurityException {
        C2248jy c2248jy = new C2248jy(abstractC2025es.getClass(), cls);
        HashMap map = this.a;
        if (map.containsKey(c2248jy)) {
            return ((C2163hy) map.get(c2248jy)).c.a(abstractC2025es);
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.B("No PrimitiveConstructor for ", c2248jy.toString(), " available, see https://developers.google.com/tink/faq/registration_errors"));
    }
}
