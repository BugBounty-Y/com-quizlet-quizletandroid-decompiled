package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public final class e {
    public final SharedPreferences a;

    public e(@NonNull Context context) {
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context).b();
    }
}
