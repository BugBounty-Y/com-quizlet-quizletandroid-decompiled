package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import java.util.UUID;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class I {
    public static final /* synthetic */ int a = 0;

    public static String a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = com.facebook.appevents.j.c;
        Intrinsics.checkNotNullParameter(context, "context");
        if (com.facebook.appevents.j.a() == null) {
            synchronized (com.facebook.appevents.j.c()) {
                try {
                    if (com.facebook.appevents.j.a() == null) {
                        String string = context.getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).getString("anonymousAppDeviceGUID", null);
                        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.j.class)) {
                            try {
                                com.facebook.appevents.j.f = string;
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.j.class, th);
                            }
                        }
                        if (com.facebook.appevents.j.a() == null) {
                            String str2 = "XZ" + UUID.randomUUID();
                            if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.j.class)) {
                                try {
                                    com.facebook.appevents.j.f = str2;
                                } catch (Throwable th2) {
                                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.j.class, th2);
                                }
                            }
                            context.getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).edit().putString("anonymousAppDeviceGUID", com.facebook.appevents.j.a()).apply();
                        }
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th3) {
                    throw th3;
                }
            }
        }
        String strA = com.facebook.appevents.j.a();
        if (strA != null) {
            return strA;
        }
        throw new IllegalStateException("Required value was null.");
    }
}
