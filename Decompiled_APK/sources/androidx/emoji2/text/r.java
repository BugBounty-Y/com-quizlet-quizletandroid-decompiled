package androidx.emoji2.text;

import android.text.TextUtils;
import android.util.Log;
import com.amazon.device.ads.DtbConstants;
import java.util.HashMap;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class r implements p {
    public static r b;
    public String a;

    public /* synthetic */ r(String str) {
        this.a = str;
    }

    public static void b(io.ktor.client.plugins.api.d dVar, com.google.firebase.crashlytics.internal.settings.d dVar2) {
        String str = dVar2.a;
        if (str != null) {
            dVar.r("X-CRASHLYTICS-GOOGLE-APP-ID", str);
        }
        dVar.r("X-CRASHLYTICS-API-CLIENT-TYPE", DtbConstants.NATIVE_OS_NAME);
        dVar.r("X-CRASHLYTICS-API-CLIENT-VERSION", "19.4.3");
        dVar.r("Accept", "application/json");
        String str2 = dVar2.b;
        if (str2 != null) {
            dVar.r("X-CRASHLYTICS-DEVICE-MODEL", str2);
        }
        String str3 = dVar2.c;
        if (str3 != null) {
            dVar.r("X-CRASHLYTICS-OS-BUILD-VERSION", str3);
        }
        String str4 = dVar2.d;
        if (str4 != null) {
            dVar.r("X-CRASHLYTICS-OS-DISPLAY-VERSION", str4);
        }
        String str5 = ((com.google.firebase.crashlytics.internal.common.v) dVar2.i).c().a;
        if (str5 != null) {
            dVar.r("X-CRASHLYTICS-INSTALLATION-ID", str5);
        }
    }

    public static HashMap c(com.google.firebase.crashlytics.internal.settings.d dVar) {
        HashMap map = new HashMap();
        map.put("build_version", (String) dVar.h);
        map.put("display_version", dVar.g);
        map.put("source", Integer.toString(dVar.e));
        String str = dVar.f;
        if (!TextUtils.isEmpty(str)) {
            map.put("instance", str);
        }
        return map;
    }

    @Override // androidx.emoji2.text.p
    public Object a() {
        return this;
    }

    @Override // androidx.emoji2.text.p
    public boolean d(CharSequence charSequence, int i, int i2, y yVar) {
        if (!TextUtils.equals(charSequence.subSequence(i, i2), this.a)) {
            return true;
        }
        yVar.c = (yVar.c & 3) | 4;
        return false;
    }

    public JSONObject e(com.android.billingclient.api.d dVar) {
        Log.isLoggable("FirebaseCrashlytics", 2);
        int i = dVar.b;
        String str = this.a;
        if (i != 200 && i != 201 && i != 202 && i != 203) {
            Log.e("FirebaseCrashlytics", "Settings request failed; (status: " + i + ") from " + str, null);
            return null;
        }
        String str2 = dVar.c;
        try {
            return new JSONObject(str2);
        } catch (Exception e) {
            Log.w("FirebaseCrashlytics", "Failed to parse settings JSON from " + str, e);
            Log.w("FirebaseCrashlytics", "Settings response " + str2, null);
            return null;
        }
    }
}
