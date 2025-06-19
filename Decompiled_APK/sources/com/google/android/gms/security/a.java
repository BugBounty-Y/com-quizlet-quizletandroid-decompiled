package com.google.android.gms.security;

import android.content.Context;
import android.util.Log;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.c;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* loaded from: classes2.dex */
public abstract class a {
    public static final c a = c.b;
    public static final Object b = new Object();
    public static Method c = null;
    public static boolean d = false;

    /* JADX WARN: Removed duplicated region for block: B:27:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0091 A[Catch: all -> 0x0067, TRY_LEAVE, TryCatch #1 {, blocks: (B:12:0x0055, B:15:0x005c, B:22:0x007f, B:23:0x0084, B:20:0x006b, B:25:0x0086, B:36:0x00e0, B:37:0x00e5, B:39:0x00e7, B:40:0x00f3, B:28:0x0091, B:30:0x0095, B:33:0x00d0), top: B:45:0x0055, inners: #0, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00e0 A[Catch: all -> 0x0067, TryCatch #1 {, blocks: (B:12:0x0055, B:15:0x005c, B:22:0x007f, B:23:0x0084, B:20:0x006b, B:25:0x0086, B:36:0x00e0, B:37:0x00e5, B:39:0x00e7, B:40:0x00f3, B:28:0x0091, B:30:0x0095, B:33:0x00d0), top: B:45:0x0055, inners: #0, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00e7 A[Catch: all -> 0x0067, TryCatch #1 {, blocks: (B:12:0x0055, B:15:0x005c, B:22:0x007f, B:23:0x0084, B:20:0x006b, B:25:0x0086, B:36:0x00e0, B:37:0x00e5, B:39:0x00e7, B:40:0x00f3, B:28:0x0091, B:30:0x0095, B:33:0x00d0), top: B:45:0x0055, inners: #0, #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(android.content.Context r12) {
        /*
            Method dump skipped, instructions count: 246
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.security.a.a(android.content.Context):void");
    }

    public static void b(Context context, String str) throws IllegalAccessException, GooglePlayServicesNotAvailableException, IllegalArgumentException, InvocationTargetException {
        try {
            if (c == null) {
                c = context.getClassLoader().loadClass(str).getMethod("insertProvider", Context.class);
            }
            c.invoke(null, context);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (Log.isLoggable("ProviderInstaller", 6)) {
                Log.e("ProviderInstaller", "Failed to install provider: ".concat(String.valueOf(cause == null ? e.toString() : cause.toString())));
            }
            throw new GooglePlayServicesNotAvailableException();
        }
    }
}
