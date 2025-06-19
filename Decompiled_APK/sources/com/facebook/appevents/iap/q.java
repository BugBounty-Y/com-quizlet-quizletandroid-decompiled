package com.facebook.appevents.iap;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3559x2;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes.dex */
public final class q {
    public static String d;
    public static final q a = new q();
    public static final ConcurrentHashMap b = new ConcurrentHashMap();
    public static final ConcurrentHashMap c = new ConcurrentHashMap();
    public static final AtomicBoolean e = new AtomicBoolean(false);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:164:0x010e A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x013d A[Catch: all -> 0x0111, TryCatch #2 {all -> 0x0111, blocks: (B:34:0x00c2, B:36:0x00e0, B:39:0x00e7, B:45:0x00f5, B:51:0x0105, B:57:0x0114, B:65:0x012f, B:69:0x013d, B:64:0x012b, B:42:0x00ec, B:46:0x00fc, B:74:0x0162, B:75:0x0167, B:78:0x0177, B:80:0x017e, B:82:0x0189, B:85:0x01a2, B:87:0x01aa, B:88:0x01b2, B:90:0x01ba, B:99:0x01f9, B:93:0x01d0, B:95:0x01d8, B:96:0x01e0, B:98:0x01e8, B:102:0x0206, B:103:0x0210, B:105:0x0216, B:107:0x021e, B:111:0x0236, B:112:0x023b, B:114:0x0241, B:116:0x025d, B:119:0x0265, B:121:0x026b, B:122:0x0273, B:123:0x027b, B:125:0x0281, B:126:0x0289, B:108:0x0229, B:61:0x0125), top: B:147:0x00c2, inners: #5 }] */
    /* JADX WARN: Type inference failed for: r0v23, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r0v44 */
    /* JADX WARN: Type inference failed for: r0v45 */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [android.os.Bundle] */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r10v3 */
    /* JADX WARN: Type inference failed for: r10v4, types: [android.os.BaseBundle] */
    /* JADX WARN: Type inference failed for: r10v5, types: [android.os.Bundle] */
    /* JADX WARN: Type inference failed for: r10v6, types: [android.os.BaseBundle] */
    /* JADX WARN: Type inference failed for: r10v7, types: [android.os.Bundle] */
    /* JADX WARN: Type inference failed for: r10v8 */
    /* JADX WARN: Type inference failed for: r23v2 */
    /* JADX WARN: Type inference failed for: r23v3, types: [java.lang.Long] */
    /* JADX WARN: Type inference failed for: r23v4, types: [java.lang.Long] */
    /* JADX WARN: Type inference failed for: r23v5 */
    /* JADX WARN: Type inference failed for: r23v6 */
    /* JADX WARN: Type inference failed for: r3v12 */
    /* JADX WARN: Type inference failed for: r3v13, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r3v27 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final synchronized android.os.Bundle c(java.util.List r30, long r31, boolean r33, java.util.List r34) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 680
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.q.c(java.util.List, long, boolean, java.util.List):android.os.Bundle");
    }

    public static final void d() {
        if (com.facebook.internal.instrument.crashshield.a.b(q.class)) {
            return;
        }
        try {
            if (e.get()) {
                s sVarA = a.a();
                int iOrdinal = sVarA.ordinal();
                if (iOrdinal == 1) {
                    d.b(s.V1);
                    return;
                }
                if (iOrdinal != 2) {
                    if (iOrdinal == 3 && C1563s.b(EnumC1562q.IapLoggingLib5To7)) {
                        f.b(com.facebook.o.a(), sVarA);
                        return;
                    }
                    return;
                }
                if (C1563s.b(EnumC1562q.IapLoggingLib2)) {
                    f.b(com.facebook.o.a(), sVarA);
                } else {
                    d.b(s.V2_V4);
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(q.class, th);
        }
    }

    public final s a() {
        String string;
        s sVar = s.V5_V7;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            Context contextA = com.facebook.o.a();
            ApplicationInfo applicationInfo = contextA.getPackageManager().getApplicationInfo(contextA.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "context.packageManager.g…TA_DATA\n                )");
            string = applicationInfo.metaData.getString("com.google.android.play.billingclient.version");
        } catch (Exception unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
        if (string == null) {
            return s.NONE;
        }
        List listSplit$default = StringsKt__StringsKt.split$default(string, new String[]{"."}, false, 3, 2, null);
        if (string.length() != 0) {
            String strConcat = "GPBL.".concat(string);
            if (!com.facebook.internal.instrument.crashshield.a.b(q.class)) {
                try {
                    d = strConcat;
                } catch (Throwable th2) {
                    com.facebook.internal.instrument.crashshield.a.a(q.class, th2);
                }
            }
            Integer intOrNull = StringsKt.toIntOrNull((String) listSplit$default.get(0));
            if (intOrNull != null) {
                int iIntValue = intOrNull.intValue();
                return iIntValue == 1 ? s.V1 : iIntValue < 5 ? s.V2_V4 : sVar;
            }
        }
        return sVar;
    }

    public final String b(Bundle bundle, com.facebook.appevents.q qVar, Bundle bundle2, com.facebook.appevents.q qVar2, boolean z, boolean z2) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                List<Pair> listC = z2 ? n.c(z) : n.b(z);
                if (listC != null) {
                    for (Pair pair : listC) {
                        Map map = com.facebook.appevents.q.b;
                        Object objC = AbstractC3559x2.c((String) pair.a, bundle, qVar);
                        String str = objC instanceof String ? (String) objC : null;
                        if (str != null && str.length() != 0) {
                            for (String str2 : (List) pair.b) {
                                Map map2 = com.facebook.appevents.q.b;
                                Object objC2 = AbstractC3559x2.c(str2, bundle2, qVar2);
                                String str3 = objC2 instanceof String ? (String) objC2 : null;
                                if (str3 != null && str3.length() != 0 && str3.equals(str)) {
                                    return z ? (String) pair.a : str2;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }
}
