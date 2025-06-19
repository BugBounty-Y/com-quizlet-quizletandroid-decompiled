package com.google.android.gms.internal.ads;

import android.media.MediaCodecInfo;
import android.os.Build;
import android.util.Pair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class ME {
    public static final HashMap a = new HashMap();

    public static String a(C1832aG c1832aG) {
        Pair pairA;
        String str = c1832aG.m;
        if ("audio/eac3-joc".equals(str)) {
            return "audio/eac3";
        }
        if ("video/dolby-vision".equals(str) && (pairA = Hi.a(c1832aG)) != null) {
            int iIntValue = ((Integer) pairA.first).intValue();
            if (iIntValue == 16 || iIntValue == 256) {
                return "video/hevc";
            }
            if (iIntValue == 512) {
                return "video/avc";
            }
            if (iIntValue == 1024) {
                return "video/av01";
            }
        }
        if ("video/mv-hevc".equals(str)) {
            return "video/hevc";
        }
        return null;
    }

    public static synchronized List b(String str, boolean z, boolean z2) {
        try {
            KE ke = new KE(str, z, z2);
            HashMap map = a;
            List list = (List) map.get(ke);
            if (list != null) {
                return list;
            }
            ArrayList arrayListD = d(ke, new com.android.billingclient.api.s(z, z2, str.equals("video/mv-hevc")));
            if (z) {
                arrayListD.isEmpty();
            }
            if ("audio/raw".equals(str)) {
                Collections.sort(arrayListD, new Cr(new TD(15), 1));
            }
            if (Build.VERSION.SDK_INT < 32 && arrayListD.size() > 1 && "OMX.qti.audio.decoder.flac".equals(((HE) arrayListD.get(0)).a)) {
                arrayListD.add((HE) arrayListD.remove(0));
            }
            AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(arrayListD);
            map.put(ke, abstractC2330luN);
            return abstractC2330luN;
        } catch (Throwable th) {
            throw th;
        }
    }

    public static Bu c(C1 c1, C1832aG c1832aG, boolean z, boolean z2) {
        Iterable iterableB;
        String str = c1832aG.m;
        c1.getClass();
        List listB = b(str, z, z2);
        String strA = a(c1832aG);
        if (strA == null) {
            iterableB = Bu.e;
        } else {
            c1.getClass();
            iterableB = b(strA, z, z2);
        }
        C2244ju c2244ju = AbstractC2330lu.b;
        C2159hu c2159hu = new C2159hu(4);
        c2159hu.f(listB);
        c2159hu.f(iterableB);
        return c2159hu.j();
    }

    /* JADX WARN: Removed duplicated region for block: B:114:0x0192 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x011a A[Catch: Exception -> 0x0124, TryCatch #2 {Exception -> 0x0124, blocks: (B:58:0x00ea, B:64:0x0101, B:70:0x0114, B:72:0x011a, B:79:0x0133, B:81:0x013c, B:82:0x0140, B:84:0x0150, B:86:0x0158, B:75:0x0128), top: B:104:0x00ea }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0128 A[Catch: Exception -> 0x0124, TryCatch #2 {Exception -> 0x0124, blocks: (B:58:0x00ea, B:64:0x0101, B:70:0x0114, B:72:0x011a, B:79:0x0133, B:81:0x013c, B:82:0x0140, B:84:0x0150, B:86:0x0158, B:75:0x0128), top: B:104:0x00ea }] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x013c A[Catch: Exception -> 0x0124, TryCatch #2 {Exception -> 0x0124, blocks: (B:58:0x00ea, B:64:0x0101, B:70:0x0114, B:72:0x011a, B:79:0x0133, B:81:0x013c, B:82:0x0140, B:84:0x0150, B:86:0x0158, B:75:0x0128), top: B:104:0x00ea }] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0140 A[Catch: Exception -> 0x0124, TryCatch #2 {Exception -> 0x0124, blocks: (B:58:0x00ea, B:64:0x0101, B:70:0x0114, B:72:0x011a, B:79:0x0133, B:81:0x013c, B:82:0x0140, B:84:0x0150, B:86:0x0158, B:75:0x0128), top: B:104:0x00ea }] */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0160  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList d(com.google.android.gms.internal.ads.KE r19, com.android.billingclient.api.s r20) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 418
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ME.d(com.google.android.gms.internal.ads.KE, com.android.billingclient.api.s):java.util.ArrayList");
    }

    public static boolean e(MediaCodecInfo mediaCodecInfo, String str) {
        if (Build.VERSION.SDK_INT >= 29) {
            return mediaCodecInfo.isSoftwareOnly();
        }
        if (AbstractC2514q5.h(str)) {
            return true;
        }
        String strF = AbstractC2543qs.f(mediaCodecInfo.getName());
        if (strF.startsWith("arc.")) {
            return false;
        }
        if (strF.startsWith("omx.google.") || strF.startsWith("omx.ffmpeg.")) {
            return true;
        }
        if ((strF.startsWith("omx.sec.") && strF.contains(".sw.")) || strF.equals("omx.qcom.video.decoder.hevcswvdec") || strF.startsWith("c2.android.") || strF.startsWith("c2.google.")) {
            return true;
        }
        return (strF.startsWith("omx.") || strF.startsWith("c2.")) ? false : true;
    }
}
