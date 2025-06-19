package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.qA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2519qA extends ThreadLocal {
    public final /* synthetic */ As a;

    public C2519qA(As as) {
        this.a = as;
    }

    @Override // java.lang.ThreadLocal
    public final Object initialValue() throws InvalidKeyException {
        try {
            C2433oA c2433oA = C2433oA.c;
            As as = this.a;
            Mac mac = (Mac) c2433oA.a.zza((String) as.c);
            mac.init((SecretKeySpec) as.d);
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
