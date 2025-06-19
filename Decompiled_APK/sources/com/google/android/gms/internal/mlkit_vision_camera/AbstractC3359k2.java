package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Build;
import android.os.Trace;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.k2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3359k2 {
    public static long a;
    public static Method b;
    public static Method c;
    public static Method d;
    public static Method e;

    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00db  */
    /* JADX WARN: Removed duplicated region for block: B:59:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r18, int r19, androidx.compose.runtime.InterfaceC0806l r20, androidx.compose.ui.q r21, java.lang.String r22, java.lang.String r23) {
        /*
            Method dump skipped, instructions count: 232
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2.a(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, java.lang.String):void");
    }

    public static okhttp3.B b(String protocol) throws IOException {
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        if (protocol.equals("http/1.0")) {
            return okhttp3.B.HTTP_1_0;
        }
        if (protocol.equals("http/1.1")) {
            return okhttp3.B.HTTP_1_1;
        }
        if (protocol.equals("h2_prior_knowledge")) {
            return okhttp3.B.H2_PRIOR_KNOWLEDGE;
        }
        if (protocol.equals("h2")) {
            return okhttp3.B.HTTP_2;
        }
        if (protocol.equals("spdy/3.1")) {
            return okhttp3.B.SPDY_3;
        }
        if (protocol.equals("quic")) {
            return okhttp3.B.QUIC;
        }
        throw new IOException("Unexpected protocol: ".concat(protocol));
    }

    public static void c(Exception exc) {
        if (exc instanceof InvocationTargetException) {
            Throwable cause = exc.getCause();
            if (!(cause instanceof RuntimeException)) {
                throw new RuntimeException(cause);
            }
            throw ((RuntimeException) cause);
        }
    }

    public static boolean d() {
        if (Build.VERSION.SDK_INT >= 29) {
            return androidx.tracing.a.c();
        }
        try {
            if (b == null) {
                a = Trace.class.getField("TRACE_TAG_APP").getLong(null);
                b = Trace.class.getMethod("isTagEnabled", Long.TYPE);
            }
            return ((Boolean) b.invoke(null, Long.valueOf(a))).booleanValue();
        } catch (Exception e2) {
            c(e2);
            return false;
        }
    }

    public static void e(int i, String str) {
        if (Build.VERSION.SDK_INT >= 29) {
            androidx.tracing.a.d(i, f(str));
            return;
        }
        String strF = f(str);
        try {
            if (e == null) {
                e = Trace.class.getMethod("traceCounter", Long.TYPE, String.class, Integer.TYPE);
            }
            e.invoke(null, Long.valueOf(a), strF, Integer.valueOf(i));
        } catch (Exception e2) {
            c(e2);
        }
    }

    public static String f(String str) {
        return str.length() <= 127 ? str : str.substring(0, 127);
    }
}
