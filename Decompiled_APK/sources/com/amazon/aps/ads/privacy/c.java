package com.amazon.aps.ads.privacy;

import android.content.Context;
import android.content.SharedPreferences;
import com.amazon.device.ads.AdRegistration;
import com.amazon.device.ads.DtbSharedPreferences;
import java.io.File;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final c f = new c();
    public final Set a;
    public boolean b;
    public final a c;
    public Boolean d;
    public final b e;

    public c() {
        String[] elements = {"IABTCF_TCString", "IABTCF_gdprApplies"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.a = C4933y.T(elements);
        this.c = new a();
        this.e = new b(this, 0);
    }

    public final String a(SharedPreferences prefs) {
        Intrinsics.checkNotNullParameter(prefs, "prefs");
        Intrinsics.checkNotNullParameter("IABTCF_TCString", "key");
        try {
            return prefs.getString("IABTCF_TCString", null);
        } catch (Exception e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 1, "Error reading the shared pref value", e);
            return null;
        }
    }

    public final boolean b() {
        Boolean bool = this.d;
        if (bool != null && bool.booleanValue()) {
            return true;
        }
        a aVar = this.c;
        Boolean bool2 = (Boolean) aVar.d;
        return (bool2 != null && Intrinsics.b(bool2, Boolean.TRUE)) || aVar.b;
    }

    public final boolean c() {
        if (!b()) {
            return true;
        }
        a aVar = this.c;
        return aVar != null && aVar.a;
    }

    public final void d() {
        File filesDir;
        if (c()) {
            return;
        }
        DtbSharedPreferences.clearStorage();
        Context context = AdRegistration.getContext();
        if (context == null || (filesDir = context.getFilesDir()) == null) {
            return;
        }
        File file = new File(Intrinsics.k("/config/aps_mobile_client_config.json", filesDir.getAbsolutePath()));
        if (file.exists()) {
            file.delete();
        }
    }
}
