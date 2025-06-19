package com.google.android.gms.analytics;

import android.text.TextUtils;
import com.amazon.device.ads.DtbDebugProperties;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.gtm.zzbr;
import com.google.android.gms.internal.gtm.zzbu;
import com.google.android.gms.internal.gtm.zzem;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/* loaded from: classes2.dex */
public final class c extends zzbr {
    public boolean a;
    public final HashMap b;
    public final HashMap c;
    public final zzem d;
    public final m e;

    public c(zzbu zzbuVar, String str) {
        super(zzbuVar);
        HashMap map = new HashMap();
        this.b = map;
        this.c = new HashMap();
        map.put("&tid", str);
        map.put(DtbDebugProperties.USE_SECURE, "1");
        map.put("&a", Integer.toString(new Random().nextInt(SubsamplingScaleImageView.TILE_SIZE_AUTO) + 1));
        this.d = new zzem(60, 2000L, "tracking", zzC());
        this.e = new m(zzbuVar);
    }

    public static void f(Map map, HashMap map2) {
        if (map == null) {
            return;
        }
        for (Map.Entry entry : map.entrySet()) {
            String strI = i(entry);
            if (strI != null) {
                map2.put(strI, (String) entry.getValue());
            }
        }
    }

    public static String i(Map.Entry entry) {
        String str = (String) entry.getKey();
        if (!str.startsWith("&") || str.length() < 2) {
            return null;
        }
        return ((String) entry.getKey()).substring(1);
    }

    public final String a() {
        zzV();
        if (TextUtils.isEmpty("&cid")) {
            return null;
        }
        HashMap map = this.b;
        return map.containsKey("&cid") ? (String) map.get("&cid") : zzv().zzb();
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:58:0x011f
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e2 A[Catch: all -> 0x011a, TRY_ENTER, TryCatch #0 {all -> 0x011a, blocks: (B:34:0x00bf, B:50:0x0106, B:45:0x00e2, B:49:0x00fb), top: B:62:0x00bf }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(java.util.Map r12) {
        /*
            Method dump skipped, instructions count: 300
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.analytics.c.d(java.util.Map):void");
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
        this.e.zzW();
        String strZza = zzB().zza();
        HashMap map = this.b;
        if (strZza != null && !TextUtils.isEmpty("&an")) {
            map.put("&an", strZza);
        }
        String strZzb = zzB().zzb();
        if (strZzb == null || TextUtils.isEmpty("&av")) {
            return;
        }
        map.put("&av", strZzb);
    }
}
