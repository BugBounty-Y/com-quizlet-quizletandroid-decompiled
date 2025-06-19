package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.yw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2890yw implements InterfaceC2289kw {
    public final C2119gy a;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [com.google.android.gms.internal.ads.ey] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2289kw
    public final byte[] a(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        List list;
        C2604sA c2604sA = C2119gy.b;
        HashMap map = this.a.a;
        List c2031ey = (List) map.get(c2604sA);
        if (bArr.length >= 5) {
            int length = bArr.length;
            list = (List) map.get(new C2604sA(5 > length ? length : 5, bArr));
        } else {
            list = null;
        }
        if (c2031ey == null && list == null) {
            c2031ey = new ArrayList();
        } else if (c2031ey == null) {
            c2031ey = list;
        } else if (list != null) {
            c2031ey = new C2031ey(list, c2031ey);
        }
        Iterator it2 = c2031ey.iterator();
        while (it2.hasNext()) {
            try {
                return ((C2847xw) it2.next()).a.a(bArr, bArr2);
            } catch (GeneralSecurityException unused) {
            }
        }
        throw new GeneralSecurityException("decryption failed");
    }
}
