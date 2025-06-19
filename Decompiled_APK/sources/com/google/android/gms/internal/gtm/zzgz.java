package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/* loaded from: classes2.dex */
final class zzgz extends Thread implements zzgx {
    private static zzgz zza;
    private final LinkedBlockingQueue zzb;
    private volatile boolean zzc;
    private volatile boolean zzd;
    private volatile zzha zze;
    private final Context zzf;
    private final a zzg;

    private zzgz(Context context) {
        super("GAThread");
        this.zzb = new LinkedBlockingQueue();
        this.zzc = false;
        this.zzd = false;
        this.zzg = b.a;
        if (context != null) {
            this.zzf = context.getApplicationContext();
        } else {
            this.zzf = null;
        }
        start();
    }

    public static zzgz zzd(Context context) {
        if (zza == null) {
            zza = new zzgz(context);
        }
        return zza;
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() {
        while (true) {
            try {
                try {
                    Runnable runnable = (Runnable) this.zzb.take();
                    if (!this.zzc) {
                        runnable.run();
                    }
                } catch (InterruptedException e) {
                    zzhi.zzc(e.toString());
                }
            } catch (Exception e2) {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                PrintStream printStream = new PrintStream(byteArrayOutputStream);
                e2.printStackTrace(printStream);
                printStream.flush();
                zzhi.zza("Error on Google TagManager Thread: ".concat(new String(byteArrayOutputStream.toByteArray())));
                zzhi.zza("Google TagManager is shutting down.");
                this.zzc = true;
            }
        }
    }

    @Override // com.google.android.gms.internal.gtm.zzgx
    public final void zza(Runnable runnable) {
        this.zzb.add(runnable);
    }

    @Override // com.google.android.gms.internal.gtm.zzgx
    public final void zzb(String str, String str2, String str3, Map map, String str4) {
        this.zzb.add(new zzgy(this, this, this.zzg.currentTimeMillis(), str, str2, str3, map, str4));
    }
}
