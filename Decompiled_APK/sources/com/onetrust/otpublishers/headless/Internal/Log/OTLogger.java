package com.onetrust.otpublishers.headless.Internal.Log;

import android.support.v4.media.session.a;
import android.util.Log;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3573a0;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/* loaded from: classes2.dex */
public class OTLogger {
    public static int a = 4;
    public static String b;
    public static File c;
    public static BufferedWriter d;
    public static int e;
    public static int f;
    public static boolean g;
    public static boolean h;

    public static String a(String str, String str2, String str3) {
        String str4;
        try {
            str4 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(new Date());
        } catch (Exception e2) {
            Log.e("OTLogger", "Error : " + e2.getMessage());
            str4 = null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(str4);
        sb.append(": /");
        sb.append(str);
        sb.append(" ");
        sb.append(str2);
        return a.t(sb, " - ", str3);
    }

    public static void b(int i, String str, String str2) throws IOException {
        if (i >= e && d != null) {
            try {
                if (e()) {
                    d = new BufferedWriter(new FileWriter(c, true));
                }
                d.write(a(i == 2 ? "V" : i == 3 ? "D" : i == 4 ? "I" : i == 5 ? "W" : i == 6 ? "E" : i == 7 ? "A" : "", str, str2));
                d.newLine();
                d.flush();
            } catch (IOException e2) {
                Log.e("OTLogger", "Error : " + e2.getMessage());
            }
        }
        if (d == null) {
            Log.e("OTLogger", "You have to call OTLogger.open(...) before starting to log");
        }
    }

    public static void c(String str, int i, String str2) {
        int i2 = a;
        if (i2 != -1 && i2 <= i) {
            switch (i) {
                case 4:
                    Log.i(str, str2);
                    break;
                case 5:
                    Log.w(str, str2);
                    break;
                case 6:
                    Log.e(str, str2);
                    break;
                case 7:
                    Log.wtf(str, str2);
                    break;
            }
        }
        if (!(h && g) && (!g || i <= 3)) {
            return;
        }
        b(i, str, str2);
    }

    public static void d(String str, String str2) {
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            c("OTLogger", 4, a.m("device : ", str, " - ", str2));
        }
        b(4, str, str2);
    }

    public static boolean e() throws IOException {
        try {
            if (c.length() <= f) {
                return false;
            }
            File file = new File(b + ".old");
            if (file.exists()) {
                file.delete();
            }
            c.renameTo(file);
            File file2 = new File(b);
            c = file2;
            file2.createNewFile();
            return true;
        } catch (IOException e2) {
            Log.e("OTLogger", "Error : " + e2.getMessage());
            return false;
        }
    }

    @Keep
    public static void open(@NonNull String str, int i, int i2) throws IOException {
        b = str;
        e = i;
        f = i2;
        File file = new File(b);
        c = file;
        if (!file.exists()) {
            try {
                c.createNewFile();
                d = new BufferedWriter(new FileWriter(c, true));
                AbstractC3573a0.a();
            } catch (IOException e2) {
                Log.e("OTLogger", "Error : " + e2.getMessage());
            }
        }
        e();
        try {
            d = new BufferedWriter(new FileWriter(c, true));
        } catch (IOException e3) {
            Log.e("OTLogger", Log.getStackTraceString(e3));
        }
    }
}
