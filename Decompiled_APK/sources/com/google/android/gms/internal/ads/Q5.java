package com.google.android.gms.internal.ads;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;

/* loaded from: classes2.dex */
public final class Q5 extends AbstractC2863yB {
    public MessageDigest c;

    public final byte[] k1(String str) throws UnsupportedEncodingException {
        byte[] bArr;
        byte[] bArrArray;
        String[] strArrSplit = str.split(" ");
        int length = strArrSplit.length;
        int i = 4;
        if (length == 1) {
            int iB = LA.b(strArrSplit[0]);
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(4);
            byteBufferAllocate.order(ByteOrder.LITTLE_ENDIAN);
            byteBufferAllocate.putInt(iB);
            bArrArray = byteBufferAllocate.array();
        } else {
            if (length < 5) {
                bArr = new byte[length + length];
                for (int i2 = 0; i2 < strArrSplit.length; i2++) {
                    int iB2 = LA.b(strArrSplit[i2]);
                    int i3 = (iB2 >> 16) ^ ((char) iB2);
                    byte b = (byte) i3;
                    byte b2 = (byte) (i3 >> 8);
                    int i4 = i2 + i2;
                    bArr[i4] = new byte[]{b, b2}[0];
                    bArr[i4 + 1] = b2;
                }
            } else {
                bArr = new byte[length];
                for (int i5 = 0; i5 < strArrSplit.length; i5++) {
                    int iB3 = LA.b(strArrSplit[i5]);
                    bArr[i5] = (byte) ((iB3 >> 24) ^ (((iB3 & 255) ^ ((iB3 >> 8) & 255)) ^ ((iB3 >> 16) & 255)));
                }
            }
            bArrArray = bArr;
        }
        this.c = V0();
        synchronized (this.a) {
            try {
                MessageDigest messageDigest = this.c;
                if (messageDigest == null) {
                    return new byte[0];
                }
                messageDigest.reset();
                this.c.update(bArrArray);
                byte[] bArrDigest = this.c.digest();
                int length2 = bArrDigest.length;
                if (length2 <= 4) {
                    i = length2;
                }
                byte[] bArr2 = new byte[i];
                System.arraycopy(bArrDigest, 0, bArr2, 0, i);
                return bArr2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
