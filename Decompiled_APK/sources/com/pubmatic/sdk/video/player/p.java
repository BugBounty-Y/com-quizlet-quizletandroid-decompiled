package com.pubmatic.sdk.video.player;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/* loaded from: classes2.dex */
public class p {
    private static List<com.pubmatic.sdk.video.vastmodels.e> a(List<com.pubmatic.sdk.video.vastmodels.e> list, @NonNull q[] qVarArr) {
        ArrayList arrayList;
        ArrayList arrayList2;
        if (list != null) {
            arrayList = new ArrayList();
            arrayList2 = new ArrayList();
            for (com.pubmatic.sdk.video.vastmodels.e eVar : list) {
                int length = qVarArr.length;
                int i = 0;
                while (true) {
                    if (i < length) {
                        q qVar = qVarArr[i];
                        String type = eVar.getType();
                        if (type == null || !type.contains(qVar.getValue())) {
                            i++;
                        } else {
                            arrayList.add(eVar);
                            if (qVar != q.MEDIA_WEBM) {
                                arrayList2.add(eVar);
                            }
                        }
                    }
                }
            }
        } else {
            arrayList = null;
            arrayList2 = null;
        }
        return (arrayList2 == null || !arrayList2.isEmpty()) ? arrayList2 : arrayList;
    }

    public static com.pubmatic.sdk.video.vastmodels.e filterMediaFiles(List<com.pubmatic.sdk.video.vastmodels.e> list, @NonNull q[] qVarArr, int i, int i2, int i3) {
        List<com.pubmatic.sdk.video.vastmodels.e> listA = a(list, qVarArr);
        if (listA == null || listA.size() <= 0) {
            return null;
        }
        if (listA.size() == 1) {
            return listA.get(0);
        }
        float f = i;
        float fA = a(listA.get(0), f, i2, i3);
        com.pubmatic.sdk.video.vastmodels.e eVar = listA.get(0);
        for (int i4 = 1; i4 < listA.size(); i4++) {
            com.pubmatic.sdk.video.vastmodels.e eVar2 = listA.get(i4);
            float fA2 = a(eVar2, f, i2, i3);
            if (fA2 < fA) {
                eVar = eVar2;
                fA = fA2;
            }
        }
        return eVar;
    }

    @NonNull
    public static Map<String, String> generateErrorQueryParams(@NonNull Context context, com.pubmatic.sdk.common.models.f fVar, com.pubmatic.sdk.video.vastmodels.e eVar) {
        HashMap map = new HashMap();
        if (fVar != null) {
            String make = fVar.getMake();
            if (make != null) {
                map.put("dmk", make);
            }
            String model = fVar.getModel();
            if (model != null) {
                map.put("dmdl", model);
            }
            String osVersion = fVar.getOsVersion();
            if (osVersion != null) {
                map.put("osv", osVersion);
            }
        }
        map.put("dmver", com.pubmatic.sdk.common.a.getVersion());
        map.put("ctyp", String.valueOf(com.pubmatic.sdk.common.i.getNetworkMonitor(context.getApplicationContext()).getConnectionType().getValue()));
        if (eVar != null) {
            int bitrate = eVar.getBitrate();
            if (bitrate != 0) {
                map.put("br", String.valueOf(bitrate));
            }
            int width = eVar.getWidth();
            int height = eVar.getHeight();
            if (width != 0 && height != 0) {
                map.put("csz", width + "x" + height);
            }
            String type = eVar.getType();
            if (type != null) {
                map.put("mt", type);
            }
        }
        return map;
    }

    public static int getBitRate(boolean z, boolean z2) {
        if (z && !z2) {
            return com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR;
        }
        if (z) {
            return 1000;
        }
        if (z2) {
            return 2000;
        }
        return com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR;
    }

    public static String getCustomProductPageClickUrl(com.pubmatic.sdk.video.vastmodels.j jVar, String str) {
        if (jVar == null) {
            return null;
        }
        String closestClickThroughURL = jVar.getClosestClickThroughURL();
        if (com.pubmatic.sdk.common.utility.o.isValidPlayStoreUrl(closestClickThroughURL)) {
            return closestClickThroughURL;
        }
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            return null;
        }
        return AbstractC0147y.d("https://play.google.com/store/apps/details?id=", str);
    }

    public static int getScaleFactor(@NonNull Context context) {
        return context.getResources().getDisplayMetrics().density >= 2.0f ? 2 : 1;
    }

    public static double getSkipOffset(double d, @NonNull com.pubmatic.sdk.video.c cVar, long j) {
        int skipAfter;
        if (cVar.getSkip() == 0) {
            if (d < 0.0d || d > cVar.getMaxDuration()) {
                skipAfter = cVar.getMaxDuration();
                d = skipAfter;
            }
        } else if (cVar.getSkip() != 1) {
            d = 0.0d;
        } else if (j > cVar.getSkipMin()) {
            d = cVar.getMaxDuration() > 0 ? cVar.getMaxDuration() : j;
            if (!cVar.isSkipAfterCompletionEnabled()) {
                skipAfter = cVar.getSkipAfter();
                d = skipAfter;
            }
        } else {
            d = j;
        }
        return Math.floor(d > 0.0d ? Math.min(j, d) : 0.0d);
    }

    public static com.pubmatic.sdk.video.vastmodels.b getSuitableEndCardCompanion(@NonNull List<com.pubmatic.sdk.video.vastmodels.b> list, float f, float f2) {
        ArrayList arrayList = new ArrayList();
        float f3 = f / f2;
        for (com.pubmatic.sdk.video.vastmodels.b bVar : list) {
            if ("end-card".equals(bVar.getRenderingMode())) {
                arrayList.add(bVar);
            }
        }
        if (arrayList.isEmpty()) {
            arrayList.addAll(list);
        }
        Iterator it2 = arrayList.iterator();
        float f4 = 9999.0f;
        float f5 = 2.1474836E9f;
        com.pubmatic.sdk.video.vastmodels.b bVar2 = null;
        while (it2.hasNext()) {
            com.pubmatic.sdk.video.vastmodels.b bVar3 = (com.pubmatic.sdk.video.vastmodels.b) it2.next();
            int width = bVar3.getWidth();
            int height = bVar3.getHeight();
            float fConvertDpToPixelWithFloatPrecession = com.pubmatic.sdk.common.utility.o.convertDpToPixelWithFloatPrecession(width);
            float fConvertDpToPixelWithFloatPrecession2 = com.pubmatic.sdk.common.utility.o.convertDpToPixelWithFloatPrecession(height);
            POBLog.debug("POBVastPlayerUtil", String.format(Locale.getDefault(), "Companion: Width x Height dp = %d x %d px = %.3f x %.3f", Integer.valueOf(width), Integer.valueOf(height), Float.valueOf(fConvertDpToPixelWithFloatPrecession), Float.valueOf(fConvertDpToPixelWithFloatPrecession2)), new Object[0]);
            float fAbs = Math.abs(1.0f - ((fConvertDpToPixelWithFloatPrecession / fConvertDpToPixelWithFloatPrecession2) / f3));
            float fAbs2 = Math.abs(fConvertDpToPixelWithFloatPrecession - f);
            if (fAbs < f4 || (fAbs == f4 && fAbs2 <= f5)) {
                bVar2 = bVar3;
                f4 = fAbs;
                f5 = fAbs2;
            }
        }
        return bVar2;
    }

    private static float a(@NonNull com.pubmatic.sdk.video.vastmodels.e eVar, float f, int i, int i2) {
        float bitrate = (eVar.getBitrate() - f) / f;
        float width = (eVar.getWidth() - i) / i;
        return Math.abs((eVar.getHeight() - i2) / i2) + Math.abs(width) + Math.abs(bitrate);
    }
}
