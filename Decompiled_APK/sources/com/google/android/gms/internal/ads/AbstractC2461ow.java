package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* renamed from: com.google.android.gms.internal.ads.ow, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2461ow {
    public static final CopyOnWriteArrayList a = new CopyOnWriteArrayList();

    public static void a(String str) throws GeneralSecurityException {
        Iterator it2 = a.iterator();
        if (!it2.hasNext()) {
            throw new GeneralSecurityException("No KMS client does support: ".concat(String.valueOf(str)));
        }
        throw android.support.v4.media.session.a.d(it2);
    }
}
