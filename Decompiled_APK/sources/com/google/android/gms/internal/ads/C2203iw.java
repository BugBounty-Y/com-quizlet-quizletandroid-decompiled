package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.util.Base64;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/* renamed from: com.google.android.gms.internal.ads.iw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2203iw extends AbstractC2802wu {
    public C2891yx e;
    public byte[] f;
    public int g;
    public int h;

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        C2891yx c2891yx = this.e;
        if (c2891yx != null) {
            return c2891yx.a;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws zzaz, zzgh {
        n(c2891yx);
        this.e = c2891yx;
        Uri uriNormalizeScheme = c2891yx.a.normalizeScheme();
        String scheme = uriNormalizeScheme.getScheme();
        AbstractC1795We.G("data".equals(scheme), "Unsupported scheme: ".concat(String.valueOf(scheme)));
        String schemeSpecificPart = uriNormalizeScheme.getSchemeSpecificPart();
        String str = Yo.a;
        String[] strArrSplit = schemeSpecificPart.split(",", -1);
        if (strArrSplit.length != 2) {
            throw new zzaz("Unexpected URI format: ".concat(String.valueOf(uriNormalizeScheme)), null, true, 0);
        }
        String str2 = strArrSplit[1];
        if (strArrSplit[0].contains(";base64")) {
            try {
                this.f = Base64.decode(str2, 0);
            } catch (IllegalArgumentException e) {
                throw new zzaz("Error while parsing Base64 encoded string: ".concat(String.valueOf(str2)), e, true, 0);
            }
        } else {
            this.f = URLDecoder.decode(str2, StandardCharsets.US_ASCII.name()).getBytes(StandardCharsets.UTF_8);
        }
        int length = this.f.length;
        long j = length;
        long j2 = c2891yx.c;
        if (j2 > j) {
            this.f = null;
            throw new zzgh();
        }
        int i = (int) j2;
        this.g = i;
        int i2 = length - i;
        this.h = i2;
        long j3 = c2891yx.d;
        if (j3 != -1) {
            this.h = (int) Math.min(i2, j3);
        }
        p(c2891yx);
        return j3 != -1 ? j3 : this.h;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        if (i2 == 0) {
            return 0;
        }
        int i3 = this.h;
        if (i3 == 0) {
            return -1;
        }
        int iMin = Math.min(i2, i3);
        byte[] bArr2 = this.f;
        String str = Yo.a;
        System.arraycopy(bArr2, this.g, bArr, i, iMin);
        this.g += iMin;
        this.h -= iMin;
        e(iMin);
        return iMin;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        if (this.f != null) {
            this.f = null;
            b();
        }
        this.e = null;
    }
}
