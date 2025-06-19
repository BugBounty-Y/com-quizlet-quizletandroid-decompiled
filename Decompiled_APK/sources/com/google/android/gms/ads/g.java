package com.google.android.gms.ads;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.client.y0;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/* loaded from: classes2.dex */
public class g {

    @NonNull
    public static final String DEVICE_ID_EMULATOR = "B3EEABB8EE11C2BE770B684D95219ECB";
    public static final int ERROR_CODE_APP_ID_MISSING = 8;
    public static final int ERROR_CODE_INTERNAL_ERROR = 0;
    public static final int ERROR_CODE_INVALID_AD_STRING = 11;
    public static final int ERROR_CODE_INVALID_REQUEST = 1;
    public static final int ERROR_CODE_MEDIATION_NO_FILL = 9;
    public static final int ERROR_CODE_NETWORK_ERROR = 2;
    public static final int ERROR_CODE_NO_FILL = 3;
    public static final int ERROR_CODE_REQUEST_ID_MISMATCH = 10;
    public static final int MAX_CONTENT_URL_LENGTH = 512;
    protected final y0 zza;

    public g(a aVar) {
        this.zza = new y0(aVar.zza);
    }

    public String getAdString() {
        return this.zza.l;
    }

    @NonNull
    public String getContentUrl() {
        return this.zza.a;
    }

    @Deprecated
    public <T extends com.google.android.gms.ads.mediation.customevent.a> Bundle getCustomEventExtrasBundle(@NonNull Class<T> cls) {
        Bundle bundle = this.zza.d.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter");
        if (bundle != null) {
            return bundle.getBundle(cls.getName());
        }
        return null;
    }

    @NonNull
    public Set<String> getKeywords() {
        return this.zza.c;
    }

    @NonNull
    public List<String> getNeighboringContentUrls() {
        y0 y0Var = this.zza;
        y0Var.getClass();
        return new ArrayList(y0Var.b);
    }

    public <T> Bundle getNetworkExtrasBundle(@NonNull Class<T> cls) {
        y0 y0Var = this.zza;
        y0Var.getClass();
        return y0Var.d.getBundle(cls.getName());
    }

    @NonNull
    public String getRequestAgent() {
        return this.zza.f;
    }

    public boolean isTestDevice(@NonNull Context context) {
        return this.zza.a(context);
    }

    public final y0 zza() {
        return this.zza;
    }
}
