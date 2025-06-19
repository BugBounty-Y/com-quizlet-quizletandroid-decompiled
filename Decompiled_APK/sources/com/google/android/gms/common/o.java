package com.google.android.gms.common;

import com.google.android.gms.common.internal.u;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final /* synthetic */ class o implements Callable {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ String b;
    public final /* synthetic */ l c;

    public /* synthetic */ o(boolean z, String str, l lVar) {
        this.a = z;
        this.b = str;
        this.c = lVar;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws NoSuchAlgorithmException {
        MessageDigest messageDigest;
        l lVar = this.c;
        int i = 0;
        boolean z = this.a;
        String str = this.b;
        String str2 = (z || !n.c(str, lVar, true, false).a) ? "not allowed" : "debug cert rejected";
        while (true) {
            if (i >= 2) {
                messageDigest = null;
                break;
            }
            try {
                messageDigest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException unused) {
            }
            if (messageDigest != null) {
                break;
            }
            i++;
        }
        u.h(messageDigest);
        return str2 + ": pkg=" + str + ", sha256=" + com.google.android.gms.common.util.c.b(messageDigest.digest(lVar.d)) + ", atk=" + z + ", ver=12451000.false";
    }
}
