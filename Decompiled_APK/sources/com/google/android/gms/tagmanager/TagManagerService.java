package com.google.android.gms.tagmanager;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.google.android.gms.common.annotation.KeepName;

@KeepName
/* loaded from: classes2.dex */
public class TagManagerService extends Service {
    public static final /* synthetic */ int a = 0;

    @Keep
    @KeepName
    public static void initialize(@NonNull Context context) {
        zzbk.zze(context);
    }

    @Override // android.app.Service
    @NonNull
    public IBinder onBind(@NonNull Intent intent) {
        return zzbk.zza(this);
    }
}
