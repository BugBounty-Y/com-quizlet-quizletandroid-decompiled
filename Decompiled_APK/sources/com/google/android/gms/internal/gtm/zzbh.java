package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import com.google.android.gms.ads.identifier.a;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class zzbh extends zzbr {
    public static boolean zza;
    private a zzb;
    private final zzfb zzc;
    private String zzd;
    private boolean zze;
    private final Object zzf;

    public zzbh(zzbu zzbuVar) {
        super(zzbuVar);
        this.zze = false;
        this.zzf = new Object();
        this.zzc = new zzfb(zzbuVar.zzr());
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0038 A[Catch: all -> 0x001b, TryCatch #4 {, blocks: (B:3:0x0001, B:5:0x000b, B:7:0x0012, B:17:0x0032, B:21:0x003a, B:71:0x013d, B:24:0x0042, B:25:0x004c, B:72:0x0140, B:75:0x0150, B:20:0x0038, B:12:0x001f, B:14:0x0023, B:16:0x002c, B:76:0x0151, B:26:0x004d, B:29:0x0052, B:31:0x006a, B:37:0x0083, B:38:0x008c, B:39:0x0091, B:45:0x009b, B:47:0x00af, B:53:0x00be, B:54:0x00d1, B:56:0x00d3, B:51:0x00ba, B:57:0x00e8, B:59:0x0101, B:61:0x0103, B:63:0x010b, B:65:0x010d, B:67:0x0115, B:68:0x0127, B:69:0x013a, B:46:0x00aa), top: B:83:0x0001, inners: #5, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0042 A[Catch: all -> 0x001b, TryCatch #4 {, blocks: (B:3:0x0001, B:5:0x000b, B:7:0x0012, B:17:0x0032, B:21:0x003a, B:71:0x013d, B:24:0x0042, B:25:0x004c, B:72:0x0140, B:75:0x0150, B:20:0x0038, B:12:0x001f, B:14:0x0023, B:16:0x002c, B:76:0x0151, B:26:0x004d, B:29:0x0052, B:31:0x006a, B:37:0x0083, B:38:0x008c, B:39:0x0091, B:45:0x009b, B:47:0x00af, B:53:0x00be, B:54:0x00d1, B:56:0x00d3, B:51:0x00ba, B:57:0x00e8, B:59:0x0101, B:61:0x0103, B:63:0x010b, B:65:0x010d, B:67:0x0115, B:68:0x0127, B:69:0x013a, B:46:0x00aa), top: B:83:0x0001, inners: #5, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0140 A[Catch: all -> 0x001b, TRY_LEAVE, TryCatch #4 {, blocks: (B:3:0x0001, B:5:0x000b, B:7:0x0012, B:17:0x0032, B:21:0x003a, B:71:0x013d, B:24:0x0042, B:25:0x004c, B:72:0x0140, B:75:0x0150, B:20:0x0038, B:12:0x001f, B:14:0x0023, B:16:0x002c, B:76:0x0151, B:26:0x004d, B:29:0x0052, B:31:0x006a, B:37:0x0083, B:38:0x008c, B:39:0x0091, B:45:0x009b, B:47:0x00af, B:53:0x00be, B:54:0x00d1, B:56:0x00d3, B:51:0x00ba, B:57:0x00e8, B:59:0x0101, B:61:0x0103, B:63:0x010b, B:65:0x010d, B:67:0x0115, B:68:0x0127, B:69:0x013a, B:46:0x00aa), top: B:83:0x0001, inners: #5, #8 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final synchronized com.google.android.gms.ads.identifier.a zzc() {
        /*
            Method dump skipped, instructions count: 343
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzbh.zzc():com.google.android.gms.ads.identifier.a");
    }

    private static String zze(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigestZze = zzff.zze("MD5");
        if (messageDigestZze == null) {
            return null;
        }
        return String.format(Locale.US, "%032X", new BigInteger(1, messageDigestZze.digest(str.getBytes())));
    }

    private final boolean zzf(String str) throws NoSuchAlgorithmException, IOException {
        try {
            String strZze = zze(str);
            zzN("Storing hashed adid.");
            FileOutputStream fileOutputStreamOpenFileOutput = zzo().openFileOutput("gaClientIdData", 0);
            fileOutputStreamOpenFileOutput.write(strZze.getBytes());
            fileOutputStreamOpenFileOutput.close();
            this.zzd = strZze;
            return true;
        } catch (IOException e) {
            zzJ("Error creating hash file", e);
            return false;
        }
    }

    public final String zza() {
        zzV();
        a aVarZzc = zzc();
        String str = aVarZzc != null ? aVarZzc.a : null;
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        return str;
    }

    public final boolean zzb() {
        zzV();
        a aVarZzc = zzc();
        return (aVarZzc == null || aVarZzc.b) ? false : true;
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
    }
}
