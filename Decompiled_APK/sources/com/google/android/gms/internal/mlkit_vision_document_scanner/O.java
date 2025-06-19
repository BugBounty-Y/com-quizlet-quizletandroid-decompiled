package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* loaded from: classes2.dex */
public abstract class O {
    public static final /* synthetic */ int a = 0;

    public static void a(Exception exc, StringBuilder sb, String str, int i) {
        sb.append(exc.getMessage());
        OTLogger.c(str, i, sb.toString());
    }
}
