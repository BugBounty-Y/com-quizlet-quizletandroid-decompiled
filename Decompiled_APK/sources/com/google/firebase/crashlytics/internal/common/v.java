package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import androidx.activity.K;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class v {
    public static final Pattern g = Pattern.compile("[^\\p{Alnum}]");
    public static final String h = Pattern.quote("/");
    public final com.google.android.gms.ads.nonagon.util.logging.csi.a a;
    public final Context b;
    public final String c;
    public final com.google.firebase.installations.d d;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g e;
    public b f;

    public v(Context context, String str, com.google.firebase.installations.d dVar, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar) {
        if (context == null) {
            throw new IllegalArgumentException("appContext must not be null");
        }
        if (str == null) {
            throw new IllegalArgumentException("appIdentifier must not be null");
        }
        this.b = context;
        this.c = str;
        this.d = dVar;
        this.e = gVar;
        this.a = new com.google.android.gms.ads.nonagon.util.logging.csi.a();
    }

    public final synchronized String a(SharedPreferences sharedPreferences, String str) {
        String lowerCase;
        lowerCase = g.matcher(UUID.randomUUID().toString()).replaceAll("").toLowerCase(Locale.US);
        Log.isLoggable("FirebaseCrashlytics", 2);
        sharedPreferences.edit().putString("crashlytics.installation.id", lowerCase).putString("firebase.installation.id", str).apply();
        return lowerCase;
    }

    public final u b(boolean z) {
        String str;
        if (!((Boolean) new K(0, com.google.firebase.crashlytics.internal.concurrency.d.d, com.google.firebase.crashlytics.internal.concurrency.c.class, "isNotMainThread", "isNotMainThread()Z", 0, 14).invoke()).booleanValue()) {
            Thread.currentThread().getName();
            Log.isLoggable("FirebaseCrashlytics", 3);
        }
        com.google.firebase.installations.d dVar = this.d;
        String str2 = null;
        if (z) {
            try {
                str = ((com.google.firebase.installations.a) S3.f(((com.google.firebase.installations.c) dVar).d(), 10000L, TimeUnit.MILLISECONDS)).a;
            } catch (Exception e) {
                Log.w("FirebaseCrashlytics", "Error getting Firebase authentication token.", e);
            }
        } else {
            str = null;
        }
        try {
            str2 = (String) S3.f(((com.google.firebase.installations.c) dVar).c(), 10000L, TimeUnit.MILLISECONDS);
        } catch (Exception e2) {
            Log.w("FirebaseCrashlytics", "Error getting Firebase installation id.", e2);
        }
        return new u(str2, str);
    }

    public final synchronized b c() {
        String str;
        b bVar = this.f;
        if (bVar != null && (bVar.b != null || !this.e.n())) {
            return this.f;
        }
        Log.isLoggable("FirebaseCrashlytics", 2);
        SharedPreferences sharedPreferences = this.b.getSharedPreferences("com.google.firebase.crashlytics", 0);
        String string = sharedPreferences.getString("firebase.installation.id", null);
        Log.isLoggable("FirebaseCrashlytics", 2);
        if (this.e.n()) {
            u uVarB = b(false);
            Log.isLoggable("FirebaseCrashlytics", 2);
            if (uVarB.a == null) {
                if (string == null) {
                    str = "SYN_" + UUID.randomUUID().toString();
                } else {
                    str = string;
                }
                uVarB = new u(str, null);
            }
            if (Objects.equals(uVarB.a, string)) {
                this.f = new b(sharedPreferences.getString("crashlytics.installation.id", null), uVarB.a, uVarB.b);
            } else {
                this.f = new b(a(sharedPreferences, uVarB.a), uVarB.a, uVarB.b);
            }
        } else if (string == null || !string.startsWith("SYN_")) {
            this.f = new b(a(sharedPreferences, "SYN_" + UUID.randomUUID().toString()), null, null);
        } else {
            this.f = new b(sharedPreferences.getString("crashlytics.installation.id", null), null, null);
        }
        Objects.toString(this.f);
        Log.isLoggable("FirebaseCrashlytics", 2);
        return this.f;
    }

    public final String d() {
        String str;
        com.google.android.gms.ads.nonagon.util.logging.csi.a aVar = this.a;
        Context context = this.b;
        synchronized (aVar) {
            try {
                if (aVar.a == null) {
                    String installerPackageName = context.getPackageManager().getInstallerPackageName(context.getPackageName());
                    if (installerPackageName == null) {
                        installerPackageName = "";
                    }
                    aVar.a = installerPackageName;
                }
                str = "".equals(aVar.a) ? null : aVar.a;
            } finally {
            }
        }
        return str;
    }
}
