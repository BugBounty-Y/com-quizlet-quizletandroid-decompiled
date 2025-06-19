package com.amazon.aps.shared.analytics;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;

/* loaded from: classes.dex */
public final class a implements Serializable {
    public final String a;
    public final String b;
    public final long c;
    public final int d;
    public final String e;
    public final String f;
    public final int g;
    public final String h;
    public final String i;
    public String j = "";
    public String k = "";

    public a(Context context, String str, int i) {
        this.e = "";
        this.h = "";
        this.i = "";
        try {
            this.a = com.amazon.aps.shared.a.h;
            this.f = "Android";
            this.g = Build.VERSION.SDK_INT;
            this.h = Build.MANUFACTURER;
            this.i = Build.MODEL;
            this.c = System.currentTimeMillis();
            this.e = context == null ? DtbDeviceDataRetriever.ORIENTATION_UNKNOWN : context.getPackageName();
            this.d = i;
            this.b = str;
        } catch (RuntimeException e) {
            Log.e("APSEvent", "Error constructing the APSEvent:", e);
        }
    }

    public final void a(Exception exc) {
        if (exc != null) {
            try {
                StringWriter stringWriter = new StringWriter();
                exc.printStackTrace(new PrintWriter(stringWriter));
                String string = stringWriter.toString();
                if (string.length() <= 2048) {
                    this.k = exc.getMessage() + "\n" + string;
                    return;
                }
                int length = (2042 - exc.getMessage().length()) / 2;
                this.k = exc.getMessage() + "..." + string.substring(0, length) + "..." + string.substring(string.length() - length);
            } catch (RuntimeException e) {
                Log.e("APSEvent", "Error in parsing the exception detail; ", e);
            }
        }
    }
}
