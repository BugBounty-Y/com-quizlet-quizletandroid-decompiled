package com.android.billingclient.api;

import android.os.Process;
import android.text.TextUtils;
import android.util.Log;
import androidx.compose.animation.d0;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.IllegalFormatException;
import java.util.Locale;

/* renamed from: com.android.billingclient.api.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1472a {
    public final /* synthetic */ int a;
    public String b;

    public static String c(String str, String str2, Object... objArr) {
        if (objArr.length > 0) {
            try {
                str2 = String.format(Locale.US, str2, objArr);
            } catch (IllegalFormatException e) {
                Log.e("PlayCore", "Unable to format ".concat(String.valueOf(str2)), e);
                str2 = androidx.compose.ui.node.B.i(str2, " [", TextUtils.join(", ", objArr), "]");
            }
        }
        return android.support.v4.media.session.a.l(str, " : ", str2);
    }

    public void a(String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 4)) {
            Log.i("PlayCore", c(this.b, str, objArr));
        }
    }

    public void b(String str, Object... objArr) {
        if (Log.isLoggable("PlayCore", 5)) {
            Log.w("PlayCore", c(this.b, str, objArr));
        }
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return d0.r(new StringBuilder(SimpleComparison.LESS_THAN_OPERATION), this.b, '>');
            default:
                return super.toString();
        }
    }

    public C1472a(String str, int i) {
        this.a = i;
        switch (i) {
            case 2:
                this.b = str;
                break;
            default:
                this.b = android.support.v4.media.session.a.j("UID: [", Process.myUid(), "]  PID: [", "] ", Process.myPid()).concat(str);
                break;
        }
    }
}
