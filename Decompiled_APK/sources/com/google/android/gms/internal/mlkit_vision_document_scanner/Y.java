package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.SharedPreferences;

/* loaded from: classes2.dex */
public abstract class Y {
    public static final /* synthetic */ int a = 0;

    public static SharedPreferences a(Context context) {
        return new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b();
    }
}
