package com.google.android.gms.ads;

import android.os.Bundle;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.client.x0;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class a {
    protected final x0 zza;

    public a() {
        x0 x0Var = new x0();
        this.zza = x0Var;
        x0Var.d.add(g.DEVICE_ID_EMULATOR);
    }

    @NonNull
    @Deprecated
    public a addCustomEventExtrasBundle(@NonNull Class<? extends com.google.android.gms.ads.mediation.customevent.a> cls, @NonNull Bundle bundle) {
        Bundle bundle2 = this.zza.b;
        if (bundle2.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter") == null) {
            bundle2.putBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter", new Bundle());
        }
        Bundle bundle3 = bundle2.getBundle("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter");
        com.google.android.gms.common.internal.u.h(bundle3);
        bundle3.putBundle(cls.getName(), bundle);
        return self();
    }

    @NonNull
    public a addCustomTargeting(@NonNull String str, @NonNull String str2) {
        if (!TextUtils.isEmpty(str2) && str2.contains(",")) {
            com.google.android.gms.ads.internal.util.client.i.h("Value " + str2 + " contains invalid character ',' (comma). The server will parse it as a list of comma-separated values.");
        }
        this.zza.e.putString(str, str2);
        return self();
    }

    @NonNull
    public a addKeyword(@NonNull String str) {
        this.zza.a.add(str);
        return self();
    }

    @NonNull
    public a addNetworkExtrasBundle(@NonNull Class<Object> cls, @NonNull Bundle bundle) {
        x0 x0Var = this.zza;
        x0Var.getClass();
        x0Var.b.putBundle(cls.getName(), bundle);
        if (cls.equals(AdMobAdapter.class) && bundle.getBoolean("_emulatorLiveAds")) {
            x0Var.d.remove(g.DEVICE_ID_EMULATOR);
        }
        return self();
    }

    public abstract a self();

    @NonNull
    public a setAdString(@NonNull String str) {
        this.zza.m = str;
        return self();
    }

    @NonNull
    public a setContentUrl(@NonNull String str) {
        com.google.android.gms.common.internal.u.i(str, "Content URL must be non-null.");
        com.google.android.gms.common.internal.u.f(str, "Content URL must be non-empty.");
        int length = str.length();
        Object[] objArr = {Integer.valueOf(g.MAX_CONTENT_URL_LENGTH), Integer.valueOf(str.length())};
        if (!(length <= 512)) {
            throw new IllegalArgumentException(String.format("Content URL must not exceed %d in length.  Provided length was %d.", objArr));
        }
        this.zza.g = str;
        return self();
    }

    @NonNull
    public a setHttpTimeoutMillis(int i) {
        this.zza.n = i;
        return self();
    }

    @NonNull
    public a setNeighboringContentUrls(@NonNull List<String> list) {
        if (list == null) {
            com.google.android.gms.ads.internal.util.client.i.h("neighboring content URLs list should not be null");
            return self();
        }
        ArrayList arrayList = this.zza.h;
        arrayList.clear();
        for (String str : list) {
            if (TextUtils.isEmpty(str)) {
                com.google.android.gms.ads.internal.util.client.i.h("neighboring content URL should not be null or empty");
            } else {
                arrayList.add(str);
            }
        }
        return self();
    }

    @NonNull
    public a setRequestAgent(@NonNull String str) {
        this.zza.j = str;
        return self();
    }

    @NonNull
    @Deprecated
    public final a zza(@NonNull String str) {
        this.zza.d.add(str);
        return self();
    }

    @NonNull
    @Deprecated
    public final a zzb(boolean z) {
        this.zza.l = z;
        return self();
    }

    @NonNull
    public final a zzc(@NonNull Bundle bundle) {
        this.zza.b.putAll(bundle);
        return self();
    }

    @NonNull
    @Deprecated
    public final a zzd(boolean z) {
        this.zza.k = z ? 1 : 0;
        return self();
    }

    @NonNull
    public a addCustomTargeting(@NonNull String str, @NonNull List<String> list) {
        if (list != null) {
            for (String str2 : list) {
                if (!TextUtils.isEmpty(str2) && str2.contains(",")) {
                    com.google.android.gms.ads.internal.util.client.i.h("Value " + str2 + " contains invalid character ',' (comma). The server will parse it as a list of comma-separated values.");
                }
            }
            this.zza.e.putString(str, TextUtils.join(",", list));
        }
        return self();
    }
}
