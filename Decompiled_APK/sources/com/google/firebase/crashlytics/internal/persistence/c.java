package com.google.firebase.crashlytics.internal.persistence;

import android.content.Context;
import android.util.Log;
import com.google.firebase.crashlytics.internal.common.f;
import com.google.firebase.crashlytics.internal.d;
import com.google.firebase.crashlytics.internal.model.C3925a0;
import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public class c {
    public final String a;
    public final File b;
    public final File c;
    public final File d;
    public final File e;
    public final File f;
    public final File g;

    public c(Context context) {
        String string;
        String str = ((C3925a0) d.a.c(context)).a;
        this.a = str;
        File filesDir = context.getFilesDir();
        this.b = filesDir;
        if (str.isEmpty()) {
            string = ".com.google.firebase.crashlytics.files.v1";
        } else {
            StringBuilder sb = new StringBuilder(".crashlytics.v3");
            sb.append(File.separator);
            sb.append(str.length() > 40 ? f.h(str) : str.replaceAll("[^a-zA-Z0-9.]", "_"));
            string = sb.toString();
        }
        File file = new File(filesDir, string);
        c(file);
        this.c = file;
        File file2 = new File(file, "open-sessions");
        c(file2);
        this.d = file2;
        File file3 = new File(file, "reports");
        c(file3);
        this.e = file3;
        File file4 = new File(file, "priority-reports");
        c(file4);
        this.f = file4;
        File file5 = new File(file, "native-reports");
        c(file5);
        this.g = file5;
    }

    public static synchronized void c(File file) {
        try {
            if (file.exists()) {
                if (file.isDirectory()) {
                    return;
                }
                file.toString();
                Log.isLoggable("FirebaseCrashlytics", 3);
                file.delete();
            }
            if (!file.mkdirs()) {
                Log.e("FirebaseCrashlytics", "Could not create Crashlytics-specific directory: " + file, null);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public static boolean d(File file) {
        File[] fileArrListFiles = file.listFiles();
        if (fileArrListFiles != null) {
            for (File file2 : fileArrListFiles) {
                d(file2);
            }
        }
        return file.delete();
    }

    public static List e(Object[] objArr) {
        return objArr == null ? Collections.EMPTY_LIST : Arrays.asList(objArr);
    }

    public final void a(String str) {
        File file = new File(this.b, str);
        if (file.exists() && d(file)) {
            file.getPath();
            Log.isLoggable("FirebaseCrashlytics", 3);
        }
    }

    public final File b(String str, String str2) {
        File file = new File(this.d, str);
        file.mkdirs();
        return new File(file, str2);
    }
}
