package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class C0 extends N {
    public static /* bridge */ /* synthetic */ int f(int i, byte[] bArr) {
        return (bArr[i + 3] & 255) | ((bArr[i] & 255) << 24) | ((bArr[i + 1] & 255) << 16) | ((bArr[i + 2] & 255) << 8);
    }
}
