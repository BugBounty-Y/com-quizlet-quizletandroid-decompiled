package com.google.android.gms.cloudmessaging;

import android.util.Log;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class e extends ClassLoader {
    @Override // java.lang.ClassLoader
    public final Class loadClass(String str, boolean z) {
        if (!Objects.equals(str, "com.google.android.gms.iid.MessengerCompat")) {
            return super.loadClass(str, z);
        }
        Log.isLoggable("CloudMessengerCompat", 3);
        return zzd.class;
    }
}
