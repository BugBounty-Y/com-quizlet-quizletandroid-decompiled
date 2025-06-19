package com.google.android.gms.internal.ads;

import java.nio.charset.Charset;
import java.security.MessageDigest;

/* loaded from: classes2.dex */
public final class S5 extends AbstractC2863yB {
    public MessageDigest c;
    public final int d;
    public final int e;

    public S5(int i) {
        super(2);
        int i2 = i >> 3;
        this.d = (i & 7) > 0 ? i2 + 1 : i2;
        this.e = i;
    }

    public final byte[] k1(String str) {
        synchronized (this.a) {
            try {
                MessageDigest messageDigestV0 = V0();
                this.c = messageDigestV0;
                if (messageDigestV0 == null) {
                    return new byte[0];
                }
                messageDigestV0.reset();
                this.c.update(str.getBytes(Charset.forName("UTF-8")));
                byte[] bArrDigest = this.c.digest();
                int length = bArrDigest.length;
                int i = this.d;
                if (length > i) {
                    length = i;
                }
                byte[] bArr = new byte[length];
                System.arraycopy(bArrDigest, 0, bArr, 0, length);
                int i2 = this.e & 7;
                if (i2 > 0) {
                    long j = 0;
                    for (int i3 = 0; i3 < length; i3++) {
                        if (i3 > 0) {
                            j <<= 8;
                        }
                        j += bArr[i3] & 255;
                    }
                    long j2 = j >>> (8 - i2);
                    while (true) {
                        i--;
                        if (i < 0) {
                            break;
                        }
                        bArr[i] = (byte) (255 & j2);
                        j2 >>>= 8;
                    }
                }
                return bArr;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
