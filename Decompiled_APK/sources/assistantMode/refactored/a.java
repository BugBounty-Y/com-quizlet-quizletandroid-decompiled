package assistantMode.refactored;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Parcel;
import androidx.camera.camera2.internal.AbstractC0147y;
import assistantMode.enums.m;
import com.braze.managers.AbstractC1490c;
import com.facebook.internal.AbstractC1554i;
import com.facebook.o;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract /* synthetic */ class a {
    public static final int a(int i) {
        o oVar = o.a;
        AbstractC1554i.k();
        return AbstractC0147y.k(i) + o.i;
    }

    public static /* synthetic */ boolean b(int i) {
        if (i == 1 || i == 2 || i == 3) {
            return false;
        }
        if (i == 4 || i == 5) {
            return true;
        }
        throw null;
    }

    public static /* synthetic */ String c(int i) {
        switch (i) {
            case 1:
                return "anon_id";
            case 2:
                return "fb_login_id";
            case 3:
                return "madid";
            case 4:
                return "page_id";
            case 5:
                return "page_scoped_user_id";
            case 6:
                return "ud";
            case 7:
                return "advertiser_tracking_enabled";
            case 8:
                return "application_tracking_enabled";
            case 9:
                return "consider_views";
            case 10:
                return "device_token";
            case 11:
                return "extInfo";
            case 12:
                return "include_dwell_data";
            case 13:
                return "include_video_data";
            case 14:
                return "install_referrer";
            case 15:
                return "installer_package";
            case 16:
                return "receipt_data";
            case 17:
                return "url_schemes";
            default:
                throw null;
        }
    }

    public static int d(int i, int i2, Map map) {
        return (map.hashCode() + i) * i2;
    }

    public static int e(m mVar, int i, int i2) {
        return (mVar.hashCode() + i) * i2;
    }

    public static long f() {
        return new Date().getTime();
    }

    public static SharedPreferences g(int i, Context context, String str, String str2, String str3) {
        return AbstractC1490c.a(context, str2, str3, new StringBuilder(str), i);
    }

    public static com.google.android.gms.dynamic.a h(Parcel parcel) {
        com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
        parcel.recycle();
        return aVarV3;
    }

    public static String i(Class cls, StringBuilder sb, String str) {
        sb.append(cls.getName());
        sb.append(str);
        return sb.toString();
    }

    public static String j(String str, JSONObject jSONObject) {
        return str + jSONObject;
    }

    public static String k(StringBuilder sb, Boolean bool, String str) {
        sb.append(bool);
        sb.append(str);
        return sb.toString();
    }

    public static String l(StringBuilder sb, Integer num, String str) {
        sb.append(num);
        sb.append(str);
        return sb.toString();
    }

    public static ArrayList m(String str, List list) {
        Intrinsics.checkNotNullParameter(list, str);
        return new ArrayList();
    }

    public static HashMap n(Class cls, com.google.firebase.encoders.proto.a aVar) {
        HashMap map = new HashMap();
        map.put(cls, aVar);
        return map;
    }

    public static Map o(HashMap map) {
        return Collections.unmodifiableMap(new HashMap(map));
    }

    public static void p(SharedPreferences sharedPreferences, String str, boolean z) {
        sharedPreferences.edit().putBoolean(str, z).apply();
    }

    public static void q(HashSet hashSet, String str, String str2, String str3, String str4) {
        hashSet.add(str);
        hashSet.add(str2);
        hashSet.add(str3);
        hashSet.add(str4);
    }

    public static /* synthetic */ String r(int i) {
        switch (i) {
            case 1:
                return "BEGIN_ARRAY";
            case 2:
                return "END_ARRAY";
            case 3:
                return "BEGIN_OBJECT";
            case 4:
                return "END_OBJECT";
            case 5:
                return "NAME";
            case 6:
                return "STRING";
            case 7:
                return "NUMBER";
            case 8:
                return "BOOLEAN";
            case 9:
                return "NULL";
            case 10:
                return "END_DOCUMENT";
            default:
                return "null";
        }
    }

    public static /* synthetic */ String s(int i) {
        switch (i) {
            case 1:
                return "INITIALIZE";
            case 2:
                return "RESOURCE_CACHE";
            case 3:
                return "DATA_CACHE";
            case 4:
                return "SOURCE";
            case 5:
                return "ENCODE";
            case 6:
                return "FINISHED";
            default:
                return "null";
        }
    }
}
