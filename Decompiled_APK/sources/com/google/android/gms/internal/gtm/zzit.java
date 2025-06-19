package com.google.android.gms.internal.gtm;

import android.content.Context;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class zzit {
    private final Context zza;

    public zzit(Context context) {
        this.zza = context;
    }

    public final String[] zza() throws IOException {
        return this.zza.getAssets().list("");
    }

    public final String[] zzb(String str) throws IOException {
        return this.zza.getAssets().list("containers");
    }
}
