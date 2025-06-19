package com.google.firebase.crashlytics.internal.metadata;

import android.util.Log;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class n implements d {
    public static final Charset c = Charset.forName("UTF-8");
    public final File a;
    public l b;

    public n(File file) {
        this.a = file;
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.d
    public final void a() throws IOException {
        com.google.firebase.crashlytics.internal.common.f.b(this.b, "There was a problem closing the Crashlytics log file.");
        this.b = null;
    }

    public final void b() {
        File file = this.a;
        if (this.b == null) {
            try {
                this.b = new l(file);
            } catch (IOException e) {
                Log.e("FirebaseCrashlytics", "Could not open log file: " + file, e);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x000a  */
    @Override // com.google.firebase.crashlytics.internal.metadata.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String f() {
        /*
            r7 = this;
            java.io.File r0 = r7.a
            boolean r0 = r0.exists()
            r1 = 0
            r2 = 0
            if (r0 != 0) goto Lc
        La:
            r4 = r1
            goto L38
        Lc:
            r7.b()
            com.google.firebase.crashlytics.internal.metadata.l r0 = r7.b
            if (r0 != 0) goto L14
            goto La
        L14:
            int[] r3 = new int[]{r2}
            int r0 = r0.y()
            byte[] r0 = new byte[r0]
            com.google.firebase.crashlytics.internal.metadata.l r4 = r7.b     // Catch: java.io.IOException -> L29
            com.google.firebase.crashlytics.internal.metadata.f r5 = new com.google.firebase.crashlytics.internal.metadata.f     // Catch: java.io.IOException -> L29
            r5.<init>(r0, r3)     // Catch: java.io.IOException -> L29
            r4.f(r5)     // Catch: java.io.IOException -> L29
            goto L31
        L29:
            r4 = move-exception
            java.lang.String r5 = "FirebaseCrashlytics"
            java.lang.String r6 = "A problem occurred while reading the Crashlytics log file."
            android.util.Log.e(r5, r6, r4)
        L31:
            com.google.firebase.crashlytics.internal.metadata.m r4 = new com.google.firebase.crashlytics.internal.metadata.m
            r3 = r3[r2]
            r4.<init>(r3, r0)
        L38:
            if (r4 != 0) goto L3c
            r3 = r1
            goto L45
        L3c:
            int r0 = r4.b
            byte[] r3 = new byte[r0]
            byte[] r4 = r4.a
            java.lang.System.arraycopy(r4, r2, r3, r2, r0)
        L45:
            if (r3 == 0) goto L4f
            java.lang.String r0 = new java.lang.String
            java.nio.charset.Charset r1 = com.google.firebase.crashlytics.internal.metadata.n.c
            r0.<init>(r3, r1)
            return r0
        L4f:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.metadata.n.f():java.lang.String");
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.d
    public final void j(long j, String str) {
        b();
        if (this.b == null) {
            return;
        }
        if (str == null) {
            str = "null";
        }
        try {
            if (str.length() > 16384) {
                str = "..." + str.substring(str.length() - 16384);
            }
            this.b.a(String.format(Locale.US, "%d %s%n", Long.valueOf(j), str.replaceAll("\r", " ").replaceAll("\n", " ")).getBytes(c));
            while (!this.b.i() && this.b.y() > 65536) {
                this.b.p();
            }
        } catch (IOException e) {
            Log.e("FirebaseCrashlytics", "There was a problem writing to the Crashlytics log.", e);
        }
    }
}
