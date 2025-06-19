package com.facebook.appevents.codeless;

import android.os.Bundle;
import android.view.View;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3570z2;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();

    public static Bundle b(com.facebook.appevents.codeless.internal.c cVar, View rootView, View hostView) {
        ArrayList arrayListA;
        Intrinsics.checkNotNullParameter(rootView, "rootView");
        Intrinsics.checkNotNullParameter(hostView, "hostView");
        Bundle bundle = new Bundle();
        List<com.facebook.appevents.codeless.internal.d> listUnmodifiableList = Collections.unmodifiableList(cVar.c);
        Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "unmodifiableList(parameters)");
        if (listUnmodifiableList != null) {
            for (com.facebook.appevents.codeless.internal.d dVar : listUnmodifiableList) {
                String str = dVar.b;
                String str2 = dVar.a;
                if (str == null || str.length() <= 0) {
                    ArrayList arrayList = dVar.c;
                    if (arrayList.size() > 0) {
                        if (Intrinsics.b(dVar.d, "relative")) {
                            String simpleName = hostView.getClass().getSimpleName();
                            Intrinsics.checkNotNullExpressionValue(simpleName, "hostView.javaClass.simpleName");
                            arrayListA = AbstractC3570z2.a(hostView, arrayList, 0, -1, simpleName);
                        } else {
                            String simpleName2 = rootView.getClass().getSimpleName();
                            Intrinsics.checkNotNullExpressionValue(simpleName2, "rootView.javaClass.simpleName");
                            arrayListA = AbstractC3570z2.a(rootView, arrayList, 0, -1, simpleName2);
                        }
                        Iterator it2 = arrayListA.iterator();
                        while (true) {
                            if (it2.hasNext()) {
                                e eVar = (e) it2.next();
                                if (eVar.a() != null) {
                                    String strI = com.facebook.appevents.codeless.internal.g.i(eVar.a());
                                    if (strI.length() > 0) {
                                        bundle.putString(str2, strI);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    bundle.putString(str2, dVar.b);
                }
            }
        }
        return bundle;
    }

    public static final void c(com.facebook.appevents.codeless.internal.c mapping, View rootView, View hostView) {
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(mapping, "mapping");
            Intrinsics.checkNotNullParameter(rootView, "rootView");
            Intrinsics.checkNotNullParameter(hostView, "hostView");
            String str = mapping.a;
            Bundle bundleB = b(mapping, rootView, hostView);
            a.d(bundleB);
            o.c().execute(new androidx.credentials.playservices.controllers.c(20, str, bundleB));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
        }
    }

    public synchronized g a() {
        g gVar;
        g gVar2;
        try {
            gVar = null;
            if (com.facebook.internal.instrument.crashshield.a.b(g.class)) {
                gVar2 = null;
            } else {
                try {
                    gVar2 = g.g;
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(g.class, th);
                }
            }
            if (gVar2 == null) {
                g gVar3 = new g();
                if (!com.facebook.internal.instrument.crashshield.a.b(g.class)) {
                    try {
                        g.g = gVar3;
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(g.class, th2);
                    }
                }
            }
            if (!com.facebook.internal.instrument.crashshield.a.b(g.class)) {
                try {
                    gVar = g.g;
                } catch (Throwable th3) {
                    com.facebook.internal.instrument.crashshield.a.a(g.class, th3);
                }
            }
            Intrinsics.e(gVar, "null cannot be cast to non-null type com.facebook.appevents.codeless.CodelessMatcher");
        } catch (Throwable th4) {
            throw th4;
        }
        return gVar;
    }

    public void d(Bundle parameters) {
        Locale locale;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(parameters, "parameters");
            String string = parameters.getString("_valueToSum");
            if (string != null) {
                double dDoubleValue = 0.0d;
                try {
                    Matcher matcher = Pattern.compile("[-+]*\\d+([.,]\\d+)*([.,]\\d+)?", 8).matcher(string);
                    if (matcher.find()) {
                        String strGroup = matcher.group(0);
                        try {
                            locale = o.a().getResources().getConfiguration().locale;
                        } catch (Exception unused) {
                            locale = null;
                        }
                        if (locale == null) {
                            locale = Locale.getDefault();
                            Intrinsics.checkNotNullExpressionValue(locale, "getDefault()");
                        }
                        dDoubleValue = NumberFormat.getNumberInstance(locale).parse(strGroup).doubleValue();
                    }
                } catch (ParseException unused2) {
                }
                parameters.putDouble("_valueToSum", dDoubleValue);
            }
            parameters.putString("_is_fb_codeless", "1");
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
