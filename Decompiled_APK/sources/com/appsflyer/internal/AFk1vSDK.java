package com.appsflyer.internal;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class AFk1vSDK extends FilterInputStream {
    private final int AFAdRevenueData;
    private int areAllFieldsValid;
    private byte[] component1;
    private int[] component2;
    private byte[] component3;
    private byte[] component4;
    private int copydefault;
    private final int getCurrencyIso4217Code;
    private final int getMediationNetwork;
    private AFk1sSDK getMonetizationNetwork;
    private int getRevenue;
    private int hashCode;
    private int toString;

    public AFk1vSDK(InputStream inputStream, int[] iArr, byte[] bArr, int i, boolean z, int i2) throws IOException {
        this(inputStream, iArr, bArr, i, false, i2, (byte) 0);
    }

    private int AFAdRevenueData() throws IOException {
        if (this.hashCode == Integer.MAX_VALUE) {
            this.hashCode = ((FilterInputStream) this).in.read();
        }
        if (this.areAllFieldsValid == 8) {
            byte[] bArr = this.component4;
            int i = this.hashCode;
            bArr[0] = (byte) i;
            if (i < 0) {
                throw new IllegalStateException("unexpected block size");
            }
            int i2 = 1;
            do {
                int i3 = ((FilterInputStream) this).in.read(this.component4, i2, 8 - i2);
                if (i3 <= 0) {
                    break;
                }
                i2 += i3;
            } while (i2 < 8);
            if (i2 < 8) {
                throw new IllegalStateException("unexpected block size");
            }
            int i4 = this.getMediationNetwork;
            if (i4 == this.AFAdRevenueData) {
                getCurrencyIso4217Code();
            } else {
                if (this.getRevenue <= i4) {
                    getCurrencyIso4217Code();
                }
                int i5 = this.getRevenue;
                if (i5 < this.AFAdRevenueData) {
                    this.getRevenue = i5 + 1;
                } else {
                    this.getRevenue = 1;
                }
            }
            int i6 = ((FilterInputStream) this).in.read();
            this.hashCode = i6;
            this.areAllFieldsValid = 0;
            this.toString = i6 < 0 ? 8 - (this.component4[7] & 255) : 8;
        }
        return this.toString;
    }

    private void getCurrencyIso4217Code() {
        if (this.copydefault == 2) {
            byte[] bArr = this.component4;
            System.arraycopy(bArr, 0, this.component3, 0, bArr.length);
        }
        byte[] bArr2 = this.component4;
        int i = ((bArr2[0] << 24) & (-16777216)) + ((bArr2[1] << 16) & 16711680) + ((bArr2[2] << 8) & 65280) + (bArr2[3] & 255);
        int i2 = ((-16777216) & (bArr2[4] << 24)) + (16711680 & (bArr2[5] << 16)) + (65280 & (bArr2[6] << 8)) + (bArr2[7] & 255);
        int i3 = this.getCurrencyIso4217Code;
        AFk1sSDK aFk1sSDK = this.getMonetizationNetwork;
        AFk1tSDK.AFAdRevenueData(i, i2, false, i3, aFk1sSDK.getCurrencyIso4217Code, aFk1sSDK.getRevenue, this.component2);
        int[] iArr = this.component2;
        int i4 = iArr[0];
        int i5 = iArr[1];
        byte[] bArr3 = this.component4;
        bArr3[0] = (byte) (i4 >> 24);
        bArr3[1] = (byte) (i4 >> 16);
        bArr3[2] = (byte) (i4 >> 8);
        bArr3[3] = (byte) i4;
        bArr3[4] = (byte) (i5 >> 24);
        bArr3[5] = (byte) (i5 >> 16);
        bArr3[6] = (byte) (i5 >> 8);
        bArr3[7] = (byte) i5;
        if (this.copydefault == 2) {
            for (int i6 = 0; i6 < 8; i6++) {
                byte[] bArr4 = this.component4;
                bArr4[i6] = (byte) (bArr4[i6] ^ this.component1[i6]);
            }
            byte[] bArr5 = this.component3;
            System.arraycopy(bArr5, 0, this.component1, 0, bArr5.length);
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final int available() throws IOException {
        AFAdRevenueData();
        return this.toString - this.areAllFieldsValid;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final boolean markSupported() {
        return false;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final int read() throws IOException {
        AFAdRevenueData();
        int i = this.areAllFieldsValid;
        if (i >= this.toString) {
            return -1;
        }
        byte[] bArr = this.component4;
        this.areAllFieldsValid = i + 1;
        return bArr[i] & 255;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final long skip(long j) throws IOException {
        long j2 = 0;
        while (j2 < j && read() != -1) {
            j2++;
        }
        return j2;
    }

    private AFk1vSDK(InputStream inputStream, int[] iArr, byte[] bArr, int i, boolean z, int i2, byte b) throws IOException {
        super(new BufferedInputStream(inputStream, 4096));
        this.getRevenue = 1;
        this.hashCode = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iMin = Math.min(Math.max(i, 3), 16);
        this.getCurrencyIso4217Code = iMin;
        this.component4 = new byte[8];
        byte[] bArr2 = new byte[8];
        this.component1 = bArr2;
        this.component3 = new byte[8];
        this.component2 = new int[2];
        this.areAllFieldsValid = 8;
        this.toString = 8;
        this.copydefault = i2;
        if (i2 == 2) {
            System.arraycopy(bArr, 0, bArr2, 0, 8);
        }
        this.getMonetizationNetwork = new AFk1sSDK(iArr, iMin, true, false);
        this.getMediationNetwork = 100;
        this.AFAdRevenueData = 100;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final int read(byte[] bArr, int i, int i2) throws IOException {
        int i3 = i + i2;
        for (int i4 = i; i4 < i3; i4++) {
            AFAdRevenueData();
            int i5 = this.areAllFieldsValid;
            if (i5 >= this.toString) {
                if (i4 == i) {
                    return -1;
                }
                return i2 - (i3 - i4);
            }
            byte[] bArr2 = this.component4;
            this.areAllFieldsValid = i5 + 1;
            bArr[i4] = bArr2[i5];
        }
        return i2;
    }
}
