package com.google.android.gms.internal.ads;

import android.os.Process;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import java.util.IllegalFormatException;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class Gw {
    public static final Gw c;
    public static final Gw d;
    public static final Gw e;
    public static final Gw f;
    public static final Gw g;
    public static final Gw h;
    public static final Gw i;
    public static final Gw j;
    public final /* synthetic */ int a;
    public String b;

    static {
        int i2 = 0;
        c = new Gw("TINK", i2);
        d = new Gw("CRUNCHY", i2);
        e = new Gw("NO_PREFIX", i2);
        int i3 = 1;
        f = new Gw("TINK", i3);
        g = new Gw("CRUNCHY", i3);
        h = new Gw("NO_PREFIX", i3);
        int i4 = 2;
        i = new Gw("TINK", i4);
        j = new Gw("NO_PREFIX", i4);
    }

    public static String e(String str, String str2, Object... objArr) {
        if (objArr.length > 0) {
            try {
                str2 = String.format(Locale.US, str2, objArr);
            } catch (IllegalFormatException e2) {
                Log.e("PlayCore", "Unable to format ".concat(str2), e2);
                str2 = androidx.compose.ui.node.B.i(str2, " [", TextUtils.join(", ", objArr), "]");
            }
        }
        return android.support.v4.media.session.a.l(str, " : ", str2);
    }

    public void a(String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 6)) {
            Log.e("PlayCore", e(this.b, str, objArr));
        }
    }

    public void b(RemoteException remoteException, String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 6)) {
            Log.e("PlayCore", e(this.b, str, objArr), remoteException);
        }
    }

    public void c(String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 4)) {
            Log.i("PlayCore", e(this.b, str, objArr));
        }
    }

    public void d(String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 5)) {
            Log.w("PlayCore", e(this.b, str, objArr));
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return this.b;
            case 1:
                return this.b;
            case 2:
                return this.b;
            default:
                return super.toString();
        }
    }

    public /* synthetic */ Gw(String str, int i2) {
        this.a = i2;
        this.b = str;
    }

    public Gw(String str) {
        this.a = 4;
        this.b = android.support.v4.media.session.a.j("UID: [", Process.myUid(), "]  PID: [", "] ", Process.myPid()).concat(str);
    }
}
