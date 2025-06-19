package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.EOFException;
import java.io.InterruptedIOException;

/* loaded from: classes2.dex */
public final class Q1 {
    public boolean a;
    public int b;
    public int c;
    public Object d;
    public Object e;

    public static void a(Context context) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        if (com.google.mlkit.common.internal.model.a.n(context, "AppDataParser")) {
            boolean z = false;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (com.google.android.gms.measurement.internal.Z.r(Boolean.FALSE, com.google.android.gms.internal.mlkit_vision_document_scanner.Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            sharedPreferences.edit().putInt("OT_SHOW_SYNC_NOTIFICATION", 10).apply();
        }
    }

    public boolean b(P p) throws InterruptedIOException {
        int i;
        boolean z = this.a;
        Kn kn = (Kn) this.e;
        if (z) {
            this.a = false;
            kn.g(0);
        }
        while (true) {
            if (this.a) {
                return true;
            }
            int i2 = this.b;
            R1 r1 = (R1) this.d;
            if (i2 < 0) {
                if (!r1.b(p, -1L) || !r1.a(p, true)) {
                    break;
                }
                int iC = r1.d;
                if ((r1.a & 1) == 1 && kn.c == 0) {
                    iC += c(0);
                    i = this.c;
                } else {
                    i = 0;
                }
                try {
                    p.p(iC);
                    this.b = i;
                    i2 = i;
                } catch (EOFException unused) {
                }
            }
            int iC2 = c(i2);
            int i3 = this.b + this.c;
            if (iC2 > 0) {
                kn.e(kn.c + iC2);
                p.h(kn.a, kn.c, iC2, false);
                kn.i(kn.c + iC2);
                this.a = r1.f[i3 + (-1)] != 255;
            }
            if (i3 == r1.c) {
                i3 = -1;
            }
            this.b = i3;
        }
        return false;
    }

    public int c(int i) {
        int i2;
        int i3 = 0;
        this.c = 0;
        do {
            int i4 = this.c;
            int i5 = i + i4;
            R1 r1 = (R1) this.d;
            if (i5 >= r1.c) {
                break;
            }
            this.c = i4 + 1;
            i2 = r1.f[i5];
            i3 += i2;
        } while (i2 == 255);
        return i3;
    }
}
