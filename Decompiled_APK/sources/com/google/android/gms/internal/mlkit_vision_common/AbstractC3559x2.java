package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.x2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3559x2 {
    public static final /* synthetic */ int a = 0;

    public static void a(String key, String value, Bundle customEventsParams, com.facebook.appevents.q operationalData) {
        com.facebook.appevents.r typeOfParameter = com.facebook.appevents.r.a;
        Intrinsics.checkNotNullParameter(typeOfParameter, "typeOfParameter");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(customEventsParams, "customEventsParams");
        Intrinsics.checkNotNullParameter(operationalData, "operationalData");
        int iK = AbstractC0147y.k(d(key));
        if (iK == 0) {
            customEventsParams.putCharSequence(key, value);
            return;
        }
        if (iK == 1) {
            operationalData.a(typeOfParameter, key, value);
        } else {
            if (iK != 2) {
                return;
            }
            operationalData.a(typeOfParameter, key, value);
            customEventsParams.putCharSequence(key, value);
        }
    }

    public static Pair b(String key, String value, Bundle bundle, com.facebook.appevents.q qVar) {
        com.facebook.appevents.r typeOfParameter = com.facebook.appevents.r.a;
        Intrinsics.checkNotNullParameter(typeOfParameter, "typeOfParameter");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        int iK = AbstractC0147y.k(d(key));
        if (iK == 0) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putCharSequence(key, value);
        } else if (iK == 1) {
            if (qVar == null) {
                qVar = new com.facebook.appevents.q();
            }
            qVar.a(typeOfParameter, key, value);
        } else if (iK == 2) {
            if (qVar == null) {
                qVar = new com.facebook.appevents.q();
            }
            if (bundle == null) {
                bundle = new Bundle();
            }
            qVar.a(typeOfParameter, key, value);
            bundle.putCharSequence(key, value);
        }
        return new Pair(bundle, qVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object c(java.lang.String r4, android.os.Bundle r5, com.facebook.appevents.q r6) {
        /*
            com.facebook.appevents.r r0 = com.facebook.appevents.r.a
            java.lang.String r1 = "typeOfParameter"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.String r1 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r1)
            r2 = 0
            if (r6 == 0) goto L2d
            java.lang.String r3 = "type"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r1)
            java.util.LinkedHashMap r6 = r6.a
            boolean r1 = r6.containsKey(r0)
            if (r1 != 0) goto L20
            goto L2d
        L20:
            java.lang.Object r6 = r6.get(r0)
            java.util.Map r6 = (java.util.Map) r6
            if (r6 == 0) goto L2d
            java.lang.Object r6 = r6.get(r4)
            goto L2e
        L2d:
            r6 = r2
        L2e:
            if (r5 == 0) goto L34
            java.lang.CharSequence r2 = r5.getCharSequence(r4)
        L34:
            if (r6 != 0) goto L37
            return r2
        L37:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3559x2.c(java.lang.String, android.os.Bundle, com.facebook.appevents.q):java.lang.Object");
    }

    public static int d(String parameter) {
        com.facebook.appevents.r typeOfParameter = com.facebook.appevents.r.a;
        Intrinsics.checkNotNullParameter(typeOfParameter, "typeOfParameter");
        Intrinsics.checkNotNullParameter(parameter, "parameter");
        Map map = com.facebook.appevents.q.b;
        Pair pair = (Pair) map.get(typeOfParameter);
        Set set = pair != null ? (Set) pair.a : null;
        Pair pair2 = (Pair) map.get(typeOfParameter);
        Set set2 = pair2 != null ? (Set) pair2.b : null;
        if (set == null || !set.contains(parameter)) {
            return (set2 == null || !set2.contains(parameter)) ? 1 : 3;
        }
        return 2;
    }
}
