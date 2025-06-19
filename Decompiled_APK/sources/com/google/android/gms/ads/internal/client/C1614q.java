package com.google.android.gms.ads.internal.client;

import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.UUID;

/* renamed from: com.google.android.gms.ads.internal.client.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1614q {
    public static final C1614q f = new C1614q();
    public final com.google.android.gms.ads.internal.util.client.c a;
    public final C1608n b;
    public final String c;
    public final VersionInfoParcel d;
    public final Random e;

    public C1614q() throws NoSuchAlgorithmException {
        com.google.android.gms.ads.internal.util.client.c cVar = new com.google.android.gms.ads.internal.util.client.c();
        cVar.a = -1.0f;
        G0 g0 = new G0("com.google.android.gms.ads.AdManagerCreatorImpl", 2);
        G0 g02 = new G0("com.google.android.gms.ads.AdLoaderBuilderCreatorImpl", 1);
        G0 g03 = new G0("com.google.android.gms.ads.MobileAdsSettingManagerCreatorImpl", 0);
        G0 g04 = new G0("com.google.android.gms.ads.NativeAdViewDelegateCreatorImpl", 3);
        G0 g05 = new G0("com.google.android.gms.ads.AdOverlayCreatorImpl", 4);
        C1608n c1608n = new C1608n();
        c1608n.a = g0;
        c1608n.b = g02;
        c1608n.c = g03;
        c1608n.d = g04;
        c1608n.e = g05;
        UUID uuidRandomUUID = UUID.randomUUID();
        byte[] byteArray = BigInteger.valueOf(uuidRandomUUID.getLeastSignificantBits()).toByteArray();
        byte[] byteArray2 = BigInteger.valueOf(uuidRandomUUID.getMostSignificantBits()).toByteArray();
        String string = new BigInteger(1, byteArray).toString();
        for (int i = 0; i < 2; i++) {
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                messageDigest.update(byteArray);
                messageDigest.update(byteArray2);
                byte[] bArr = new byte[8];
                System.arraycopy(messageDigest.digest(), 0, bArr, 0, 8);
                string = new BigInteger(1, bArr).toString();
            } catch (NoSuchAlgorithmException unused) {
            }
        }
        VersionInfoParcel versionInfoParcel = new VersionInfoParcel(0, ModuleDescriptor.MODULE_VERSION, true, false);
        Random random = new Random();
        this.a = cVar;
        this.b = c1608n;
        this.c = string;
        this.d = versionInfoParcel;
        this.e = random;
    }
}
