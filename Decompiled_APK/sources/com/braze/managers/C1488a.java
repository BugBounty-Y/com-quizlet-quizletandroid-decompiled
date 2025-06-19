package com.braze.managers;

import android.content.Context;
import com.amazon.device.messaging.development.ADMManifest;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.managers.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1488a {
    public static final String b() {
        return "com.amazon.device.messaging.ADM not found";
    }

    public final boolean a() throws ClassNotFoundException {
        try {
            Class.forName("com.amazon.device.messaging.ADM");
            return true;
        } catch (Exception unused) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(20), 6, (Object) null);
            return false;
        }
    }

    public final boolean a(Context context) {
        try {
            ADMManifest.checkManifestAuthoredProperly(context);
            return true;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.communication.dust.i(1, e), 6, (Object) null);
            return false;
        }
    }

    public static final String a(Exception exc) {
        return "Manifest not authored properly to support ADM. ADM manifest exception: " + exc;
    }
}
