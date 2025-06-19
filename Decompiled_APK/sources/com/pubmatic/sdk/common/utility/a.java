package com.pubmatic.sdk.common.utility;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes2.dex */
public class a {
    private static volatile a a;

    @NonNull
    private final ExecutorService b = Executors.newSingleThreadExecutor();

    @NonNull
    private final Context c;
    private Future<?> d;

    /* renamed from: com.pubmatic.sdk.common.utility.a$a, reason: collision with other inner class name */
    public class RunnableC0013a implements Runnable {
        public RunnableC0013a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                com.google.android.gms.ads.identifier.a aVarA = com.google.android.gms.ads.identifier.b.a(a.this.c);
                String str = aVarA.a;
                boolean z = aVarA.b;
                if (str != null && !str.equals(a.this.getStoredAdvertisingId())) {
                    a.this.saveAndroidAid(str);
                }
                if (z != a.this.getStoredLMTState()) {
                    a.this.saveLMTState(z);
                }
            } catch (Exception | NoClassDefFoundError e) {
                POBLog.error("POBAdvertisingIdClient", "Error while requesting AAID: ", e.getMessage());
            }
        }
    }

    private a(@NonNull Context context) {
        this.c = context.getApplicationContext();
    }

    public static a getInstance(@NonNull Context context) {
        if (a == null) {
            synchronized (a.class) {
                try {
                    if (a == null) {
                        a = new a(context);
                    }
                } finally {
                }
            }
        }
        return a;
    }

    public String getStoredAdvertisingId() {
        return this.c.getSharedPreferences("aid_shared_preference", 0).getString("aid_key", null);
    }

    public boolean getStoredLMTState() {
        return this.c.getSharedPreferences("aid_shared_preference", 0).getBoolean("limited_tracking_ad_key", false);
    }

    public boolean isReadyToUpdate() {
        Future<?> future = this.d;
        if (future != null) {
            return future.isDone();
        }
        return true;
    }

    public void saveAndroidAid(@NonNull String str) {
        SharedPreferences.Editor editorEdit = this.c.getSharedPreferences("aid_shared_preference", 0).edit();
        if (editorEdit != null) {
            editorEdit.putString("aid_key", str);
            editorEdit.apply();
        }
    }

    public void saveLMTState(boolean z) {
        SharedPreferences.Editor editorEdit = this.c.getSharedPreferences("aid_shared_preference", 0).edit();
        if (editorEdit != null) {
            editorEdit.putBoolean("limited_tracking_ad_key", z);
            editorEdit.apply();
        }
    }

    public boolean updateAAID() {
        if (isReadyToUpdate()) {
            a();
            return true;
        }
        POBLog.debug("POBAdvertisingIdClient", "Skipping AAID update as last request is in progress", new Object[0]);
        return false;
    }

    private void a() {
        try {
            this.d = this.b.submit(new RunnableC0013a());
        } catch (OutOfMemoryError | RejectedExecutionException e) {
            POBLog.error("POBAdvertisingIdClient", "Unable to dispatch thread while requesting AAID: ", e.getMessage());
        }
    }
}
