package com.google.android.gms.internal.measurement;

import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.measurement.z1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3088z1 implements androidx.arch.core.util.a {
    public static volatile com.google.common.base.i a;
    public static final /* synthetic */ int b = 0;

    public static androidx.camera.core.impl.f0 a(Context context, Bundle bundle) {
        boolean z = bundle.getBoolean("androidx.camera.core.quirks.DEFAULT_QUIRK_ENABLED", true);
        String[] strArrC = c(context, "androidx.camera.core.quirks.FORCE_ENABLED", bundle);
        String[] strArrC2 = c(context, "androidx.camera.core.quirks.FORCE_DISABLED", bundle);
        AbstractC3053s1.f(3, "QuirkSettingsLoader");
        AbstractC3053s1.f(3, "QuirkSettingsLoader");
        Arrays.toString(strArrC);
        AbstractC3053s1.f(3, "QuirkSettingsLoader");
        Arrays.toString(strArrC2);
        AbstractC3053s1.f(3, "QuirkSettingsLoader");
        return new androidx.camera.core.impl.f0(z, new HashSet(d(strArrC)), new HashSet(d(strArrC2)));
    }

    public static SpannableStringBuilder b(String stringToColor, List coloredStrings) {
        Intrinsics.checkNotNullParameter(stringToColor, "stringToColor");
        Intrinsics.checkNotNullParameter(coloredStrings, "coloredStrings");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(stringToColor);
        Iterator it2 = coloredStrings.iterator();
        while (it2.hasNext()) {
            com.quizlet.qutils.string.h hVar = (com.quizlet.qutils.string.h) it2.next();
            boolean zG = StringsKt.G(stringToColor, hVar.a, false);
            String str = hVar.a;
            if (zG) {
                spannableStringBuilder.setSpan(new ForegroundColorSpan(hVar.b), StringsKt.M(stringToColor, str, 0, false, 6), str.length() + StringsKt.M(stringToColor, str, 0, false, 6), 33);
            } else {
                timber.log.c.a.d(android.support.v4.media.session.a.l(str, " not part of the whole string ", stringToColor), new Object[0]);
            }
        }
        return spannableStringBuilder;
    }

    public static String[] c(Context context, String str, Bundle bundle) {
        if (!bundle.containsKey(str)) {
            return new String[0];
        }
        int i = bundle.getInt(str, -1);
        if (i == -1) {
            AbstractC3053s1.h("QuirkSettingsLoader", "Resource ID not found for key: ".concat(str));
            return new String[0];
        }
        try {
            return context.getResources().getStringArray(i);
        } catch (Resources.NotFoundException e) {
            AbstractC3053s1.i("QuirkSettingsLoader", "Quirk class names resource not found: " + i, e);
            return new String[0];
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0047 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.HashSet d(java.lang.String[] r8) throws java.lang.ClassNotFoundException {
        /*
            java.util.HashSet r0 = new java.util.HashSet
            r0.<init>()
            int r1 = r8.length
            r2 = 0
        L7:
            if (r2 >= r1) goto L4a
            r3 = r8[r2]
            java.lang.String r4 = "QuirkSettingsLoader"
            java.lang.Class r5 = java.lang.Class.forName(r3)     // Catch: java.lang.ClassNotFoundException -> L2f
            java.lang.Class<androidx.camera.core.impl.e0> r6 = androidx.camera.core.impl.e0.class
            boolean r6 = r6.isAssignableFrom(r5)     // Catch: java.lang.ClassNotFoundException -> L2f
            if (r6 == 0) goto L1a
            goto L42
        L1a:
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.ClassNotFoundException -> L2f
            r5.<init>()     // Catch: java.lang.ClassNotFoundException -> L2f
            r5.append(r3)     // Catch: java.lang.ClassNotFoundException -> L2f
            java.lang.String r6 = " does not implement the Quirk interface."
            r5.append(r6)     // Catch: java.lang.ClassNotFoundException -> L2f
            java.lang.String r5 = r5.toString()     // Catch: java.lang.ClassNotFoundException -> L2f
            com.google.android.gms.internal.measurement.AbstractC3053s1.h(r4, r5)     // Catch: java.lang.ClassNotFoundException -> L2f
            goto L41
        L2f:
            r5 = move-exception
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            java.lang.String r7 = "Class not found: "
            r6.<init>(r7)
            r6.append(r3)
            java.lang.String r3 = r6.toString()
            com.google.android.gms.internal.measurement.AbstractC3053s1.i(r4, r3, r5)
        L41:
            r5 = 0
        L42:
            if (r5 == 0) goto L47
            r0.add(r5)
        L47:
            int r2 = r2 + 1
            goto L7
        L4a:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.AbstractC3088z1.d(java.lang.String[]):java.util.HashSet");
    }
}
