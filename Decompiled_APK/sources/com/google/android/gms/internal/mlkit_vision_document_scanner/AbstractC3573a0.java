package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Build;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3573a0 {
    public static final /* synthetic */ int a = 0;

    public static void a() {
        OTLogger.d("***********************************", "DEVICE LOGS -***********************************");
        OTLogger.d("MODEL", Build.MODEL);
        OTLogger.d("Manufacture", Build.MANUFACTURER);
        OTLogger.d("SDK", Build.VERSION.SDK);
        OTLogger.d("BRAND", Build.BRAND);
        OTLogger.d("Version Code", Build.VERSION.RELEASE);
        OTLogger.d("***********************************", "SDK LOGS -***********************************");
    }
}
