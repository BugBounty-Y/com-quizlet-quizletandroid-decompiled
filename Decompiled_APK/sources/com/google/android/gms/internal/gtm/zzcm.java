package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.analytics.i;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

/* loaded from: classes2.dex */
public final class zzcm extends zzbr {
    private volatile String zza;
    private Future zzb;

    public zzcm(zzbu zzbuVar) {
        super(zzbuVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String zzf() throws IOException {
        String lowerCase = UUID.randomUUID().toString().toLowerCase(Locale.US);
        try {
            Context context = zzq().a;
            u.e(lowerCase);
            u.g("ClientId should be saved from worker thread");
            FileOutputStream fileOutputStreamOpenFileOutput = null;
            try {
                try {
                    zzO("Storing clientId", lowerCase);
                    fileOutputStreamOpenFileOutput = context.openFileOutput("gaClientId", 0);
                    fileOutputStreamOpenFileOutput.write(lowerCase.getBytes());
                    try {
                        fileOutputStreamOpenFileOutput.close();
                        return lowerCase;
                    } catch (IOException e) {
                        zzJ("Failed to close clientId writing stream", e);
                        return lowerCase;
                    }
                } catch (FileNotFoundException e2) {
                    zzJ("Error creating clientId file", e2);
                    if (fileOutputStreamOpenFileOutput != null) {
                        try {
                            fileOutputStreamOpenFileOutput.close();
                        } catch (IOException e3) {
                            e = e3;
                            zzJ("Failed to close clientId writing stream", e);
                            return "0";
                        }
                    }
                    return "0";
                } catch (IOException e4) {
                    zzJ("Error writing to clientId file", e4);
                    if (fileOutputStreamOpenFileOutput != null) {
                        try {
                            fileOutputStreamOpenFileOutput.close();
                        } catch (IOException e5) {
                            e = e5;
                            zzJ("Failed to close clientId writing stream", e);
                            return "0";
                        }
                    }
                    return "0";
                }
            } finally {
            }
        } catch (Exception e6) {
            zzJ("Error saving clientId file", e6);
            return "0";
        }
    }

    public final String zzb() {
        String str;
        Future futureSubmit;
        zzV();
        synchronized (this) {
            try {
                if (this.zza == null) {
                    j jVarZzq = zzq();
                    zzck zzckVar = new zzck(this);
                    jVarZzq.getClass();
                    if (Thread.currentThread() instanceof i) {
                        FutureTask futureTask = new FutureTask(zzckVar);
                        futureTask.run();
                        futureSubmit = futureTask;
                    } else {
                        futureSubmit = jVarZzq.b.submit(zzckVar);
                    }
                    this.zzb = futureSubmit;
                }
                Future future = this.zzb;
                if (future != null) {
                    try {
                        this.zza = (String) future.get();
                    } catch (InterruptedException e) {
                        zzR("ClientId loading or generation was interrupted", e);
                        this.zza = "0";
                    } catch (ExecutionException e2) {
                        zzJ("Failed to load or generate client id", e2);
                        this.zza = "0";
                    }
                    if (this.zza == null) {
                        this.zza = "0";
                    }
                    zzO("Loaded clientId", this.zza);
                    this.zzb = null;
                }
                str = this.zza;
            } catch (Throwable th) {
                throw th;
            }
        }
        return str;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0075 A[Catch: IOException -> 0x0032, TRY_ENTER, TRY_LEAVE, TryCatch #6 {IOException -> 0x0032, blocks: (B:8:0x002e, B:19:0x004a, B:34:0x0075, B:44:0x0087), top: B:54:0x0010 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0087 A[Catch: IOException -> 0x0032, TRY_ENTER, TRY_LEAVE, TryCatch #6 {IOException -> 0x0032, blocks: (B:8:0x002e, B:19:0x004a, B:34:0x0075, B:44:0x0087), top: B:54:0x0010 }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0091 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x007b A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:11:0x0033 -> B:50:0x008a). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:33:0x0073 -> B:50:0x008a). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:34:0x0075 -> B:50:0x008a). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:44:0x0087 -> B:53:0x008a). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String zzc() throws java.lang.Throwable {
        /*
            r9 = this;
            java.lang.String r0 = "gaClientId"
            java.lang.String r1 = "Failed to close client id reading stream"
            com.google.android.gms.analytics.j r2 = r9.zzq()
            android.content.Context r2 = r2.a
            java.lang.String r3 = "ClientId should be loaded from worker thread"
            com.google.android.gms.common.internal.u.g(r3)
            r3 = 0
            java.io.FileInputStream r4 = r2.openFileInput(r0)     // Catch: java.lang.Throwable -> L67 java.io.IOException -> L69 java.io.FileNotFoundException -> L84
            r5 = 36
            byte[] r6 = new byte[r5]     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r7 = 0
            int r5 = r4.read(r6, r7, r5)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            int r8 = r4.available()     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            if (r8 <= 0) goto L3b
            java.lang.String r5 = "clientId file seems corrupted, deleting it."
            r9.zzQ(r5)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r4.close()     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r2.deleteFile(r0)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r4.close()     // Catch: java.io.IOException -> L32
            goto L8a
        L32:
            r0 = move-exception
            r9.zzJ(r1, r0)
            goto L8a
        L37:
            r0 = move-exception
            goto L65
        L39:
            r5 = move-exception
            goto L6b
        L3b:
            r8 = 14
            if (r5 >= r8) goto L4e
            java.lang.String r5 = "clientId file is empty, deleting it."
            r9.zzQ(r5)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r4.close()     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r2.deleteFile(r0)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r4.close()     // Catch: java.io.IOException -> L32
            goto L8a
        L4e:
            r4.close()     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            java.lang.String r8 = new java.lang.String     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r8.<init>(r6, r7, r5)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            java.lang.String r5 = "Read client id from disk"
            r9.zzO(r5, r8)     // Catch: java.lang.Throwable -> L37 java.io.IOException -> L39 java.io.FileNotFoundException -> L85
            r4.close()     // Catch: java.io.IOException -> L5f
            goto L63
        L5f:
            r0 = move-exception
            r9.zzJ(r1, r0)
        L63:
            r3 = r8
            goto L8a
        L65:
            r3 = r4
            goto L79
        L67:
            r0 = move-exception
            goto L79
        L69:
            r5 = move-exception
            r4 = r3
        L6b:
            java.lang.String r6 = "Error reading client id file, deleting it"
            r9.zzJ(r6, r5)     // Catch: java.lang.Throwable -> L37
            r2.deleteFile(r0)     // Catch: java.lang.Throwable -> L37
            if (r4 == 0) goto L8a
            r4.close()     // Catch: java.io.IOException -> L32
            goto L8a
        L79:
            if (r3 == 0) goto L83
            r3.close()     // Catch: java.io.IOException -> L7f
            goto L83
        L7f:
            r2 = move-exception
            r9.zzJ(r1, r2)
        L83:
            throw r0
        L84:
            r4 = r3
        L85:
            if (r4 == 0) goto L8a
            r4.close()     // Catch: java.io.IOException -> L32
        L8a:
            if (r3 != 0) goto L91
            java.lang.String r0 = r9.zzf()
            return r0
        L91:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzcm.zzc():java.lang.String");
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
    }

    public final String zze() {
        Future futureSubmit;
        synchronized (this) {
            this.zza = null;
            j jVarZzq = zzq();
            zzcl zzclVar = new zzcl(this);
            jVarZzq.getClass();
            if (Thread.currentThread() instanceof i) {
                FutureTask futureTask = new FutureTask(zzclVar);
                futureTask.run();
                futureSubmit = futureTask;
            } else {
                futureSubmit = jVarZzq.b.submit(zzclVar);
            }
            this.zzb = futureSubmit;
        }
        return zzb();
    }
}
