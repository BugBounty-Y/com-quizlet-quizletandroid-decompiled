package com.amazon.aps.shared;

import android.content.Context;
import android.util.Base64;
import android.util.Log;
import androidx.appcompat.app.K;
import com.airbnb.lottie.network.d;
import com.amazon.aps.shared.metrics.model.c;
import com.amazon.aps.shared.metrics.model.n;
import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3550w;
import java.util.HashMap;
import java.util.Random;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class a {
    public static c a = new c(null, null, null, null, null);
    public static n b = new n(null);
    public static double c = 0.1d;
    public static String d = "https://prod.tahoe-analytics.publishers.advertising.a2z.com/logevent/putRecord";
    public static String e = "a5c71f6aff54eb34c826d952c285eaf0650b4259c83ae598962681a6429b63f6";
    public static boolean f = false;
    public static Context g = null;
    public static String h = "1.0";
    public static Context i = null;
    public static boolean j = false;
    public static String k;
    public static String l;
    public static String m;

    public static void a(String str, d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        com.amazon.aps.ads.c.a();
        try {
            if ((g == null || !f || AbstractC3550w.a(e) || AbstractC3550w.a(d)) ? false : true) {
                if (K.c == null) {
                    K.c = new K(5);
                }
                K k2 = K.c;
                builder.r(str);
                JSONObject jSONObjectF = builder.f();
                k2.getClass();
                if (jSONObjectF != null) {
                    k2.G(d, e, jSONObjectF.toString());
                }
            }
        } catch (RuntimeException e2) {
            e(1, 1, "Error sending the ad event", e2);
        }
    }

    public static void b() {
        try {
            boolean z = true;
            if (new Random().nextInt(10000000) + 1 > kotlin.math.c.a(c * 100000)) {
                z = false;
            }
            f = z;
        } catch (RuntimeException e2) {
            com.amazon.aps.ads.c.b("APSAndroidShared", Intrinsics.k(e2, "Unable to set the sampling rate "));
        }
    }

    public static void c(JSONObject extraAttributes, String eventName, String eventValue) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        try {
            Intrinsics.k(eventName, "Logging custom event:");
            com.amazon.aps.ads.c.a();
            if ((g == null || !f || AbstractC3550w.a(e) || AbstractC3550w.a(d)) ? false : true) {
                C1721Kc c1721Kc = new C1721Kc();
                c1721Kc.e = "custom";
                Intrinsics.checkNotNullParameter(eventName, "eventName");
                c1721Kc.b = eventName;
                if (eventValue != null) {
                    Intrinsics.checkNotNullParameter(eventValue, "eventValue");
                    c1721Kc.c = eventValue;
                }
                if (extraAttributes != null) {
                    Intrinsics.checkNotNullParameter(extraAttributes, "extraAttributes");
                    c1721Kc.d = extraAttributes;
                }
                JSONObject jSONObjectD = c1721Kc.d();
                if (jSONObjectD == null) {
                    return;
                }
                if (K.c == null) {
                    K.c = new K(5);
                }
                K k2 = K.c;
                k2.getClass();
                k2.G(d, e, jSONObjectD.toString());
            }
        } catch (RuntimeException e2) {
            e(1, 1, "Error in sending the custom event", e2);
        }
    }

    public static void d(Context context) {
        i = context;
        k = "e9026ffd475a1a3691e6b2ce637a9b92aab1073ebf53a67c5f2583be8a804ecb";
        g(1);
        l = "https://prod.cm.publishers.advertising.a2z.com/logrecord/putlog";
        m = "";
        new HashMap();
    }

    public static void e(int i2, int i3, String str, Exception exc) {
        String str2;
        try {
            com.amazon.aps.ads.c.b("APSAnalytics", str + exc);
            Context context = i;
            if (context != null && j) {
                if (i3 == 1) {
                    str2 = "EXCEPTION";
                } else {
                    if (i3 != 2) {
                        throw null;
                    }
                    str2 = "LOG";
                }
                com.amazon.aps.shared.analytics.a aVar = new com.amazon.aps.shared.analytics.a(context, str2, i2);
                aVar.a(exc);
                if (str != null) {
                    int length = str.length();
                    if (length > 2048) {
                        length = 2048;
                    }
                    aVar.j = str.substring(0, length);
                }
                f(aVar);
            }
        } catch (RuntimeException e2) {
            Log.e("APSAnalytics", "Error in processing the event: ", e2);
        }
    }

    public static void f(com.amazon.aps.shared.analytics.a aVar) throws JSONException {
        String str;
        if (aVar.d == 1) {
            if (K.c == null) {
                K.c = new K(5);
            }
            K k2 = K.c;
            k2.getClass();
            if (aVar.d == 1) {
                String str2 = l;
                String str3 = k;
                long j2 = aVar.c;
                String strReplace = "";
                String strB = android.support.v4.media.session.a.B("msg = ", aVar.j, ";");
                String str4 = m;
                if (!AbstractC3550w.a(str4)) {
                    strB = strB.concat(str4);
                }
                try {
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("sdkVersion", aVar.a);
                    jSONObject.put("eventType", aVar.b);
                    jSONObject.put("eventTimestamp", j2);
                    int i2 = aVar.d;
                    if (i2 == 1) {
                        str = "FATAL";
                    } else if (i2 == 2) {
                        str = "ERROR";
                    } else if (i2 == 3) {
                        str = "INFO";
                    } else if (i2 == 4) {
                        str = "WARN";
                    } else {
                        if (i2 != 5) {
                            throw null;
                        }
                        str = "DEBUG";
                    }
                    jSONObject.put("severity", str);
                    jSONObject.put("appId", aVar.e);
                    jSONObject.put("osName", aVar.f);
                    jSONObject.put(DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY, aVar.g);
                    jSONObject.put("deviceManufacturer", aVar.h);
                    jSONObject.put("deviceModel", aVar.i);
                    jSONObject.put("configVersion", "");
                    jSONObject.put("otherDetails", strB);
                    jSONObject.put("exceptionDetails", aVar.k);
                    strReplace = Base64.encodeToString(jSONObject.toString().getBytes(), 0).replace("\n", "");
                } catch (RuntimeException | JSONException e2) {
                    Log.e("APSEvent", "Error in parsing the json .. ignoring : ", e2);
                }
                k2.G(str2, str3, "{\"Data\": \"" + strReplace + "\",\"PartitionKey\": \"" + j2 + "\"}");
            }
        }
    }

    public static void g(int i2) {
        boolean z = true;
        if (i2 < 0 || i2 > 100) {
            Log.e("APSAnalytics", "Invalid sampling rate - setting the default one");
            i2 = 1;
        }
        try {
            if (new Random().nextInt(100) + 1 > i2) {
                z = false;
            }
            j = z;
        } catch (RuntimeException e2) {
            Log.e("APSAnalytics", "Unable to set the sampling rate", e2);
        }
    }
}
