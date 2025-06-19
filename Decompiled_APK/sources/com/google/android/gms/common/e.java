package com.google.android.gms.common;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.util.Log;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public class e {
    public static e c;
    public final Context a;
    public volatile String b;

    public e(@NonNull Context context) {
        this.a = context.getApplicationContext();
    }

    public static e a(Context context) {
        u.h(context);
        synchronized (e.class) {
            if (c == null) {
                j jVar = n.a;
                synchronized (n.class) {
                    if (n.e == null) {
                        n.e = context.getApplicationContext();
                    } else {
                        Log.w("GoogleCertificates", "GoogleCertificates has been initialized already");
                    }
                }
                c = new e(context);
            }
        }
        return c;
    }

    /* JADX WARN: Code restructure failed: missing block: B:70:0x00f7, code lost:
    
        r5 = r9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean c(android.content.pm.PackageInfo r12, boolean r13) {
        /*
            Method dump skipped, instructions count: 295
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.e.c(android.content.pm.PackageInfo, boolean):boolean");
    }

    public static k d(PackageInfo packageInfo, k... kVarArr) {
        Signature[] signatureArr = packageInfo.signatures;
        if (signatureArr != null) {
            if (signatureArr.length != 1) {
                Log.w("GoogleSignatureVerifier", "Package has more than one signature.");
                return null;
            }
            l lVar = new l(packageInfo.signatures[0].toByteArray());
            for (int i = 0; i < kVarArr.length; i++) {
                if (kVarArr[i].equals(lVar)) {
                    return kVarArr[i];
                }
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:72:0x0145  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(int r20) throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 408
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.e.b(int):boolean");
    }
}
