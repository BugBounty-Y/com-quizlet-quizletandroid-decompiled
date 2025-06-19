package com.google.android.gms.internal.measurement;

import android.net.Uri;

/* renamed from: com.google.android.gms.internal.measurement.q1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3044q1 {
    public static final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d a;

    static {
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar;
        Uri uri = AbstractC3048r1.a;
        synchronized (AbstractC3053s1.class) {
            try {
                if (AbstractC3053s1.a == null) {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = new com.onetrust.otpublishers.headless.UI.TVUI.datautils.d();
                    synchronized (AbstractC3053s1.class) {
                        if (AbstractC3053s1.a != null) {
                            throw new IllegalStateException("init() already called");
                        }
                        AbstractC3053s1.a = dVar2;
                    }
                }
                dVar = AbstractC3053s1.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        a = dVar;
    }
}
