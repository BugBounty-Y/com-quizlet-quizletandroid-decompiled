package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/* loaded from: classes2.dex */
public abstract class Qs {
    public static final String h = new UUID(0, 0).toString();
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final Ps f;
    public final Os g;

    public Qs(Context context, String str, String str2, String str3) {
        if (Ps.c == null) {
            Ps.c = new Ps(context);
        }
        this.f = Ps.c;
        this.g = Os.e(context);
        this.a = str;
        this.b = str.concat("_3p");
        this.c = str2;
        this.d = str2.concat("_3p");
        this.e = str3;
    }

    public final Ns a(long j, String str, String str2, boolean z) throws IOException {
        String str3 = this.b;
        Ps ps = this.f;
        if (str != null) {
            try {
                UUID.fromString(str);
                if (!str.equals(h)) {
                    String string = ((SharedPreferences) ps.b).getString(str3, null);
                    String string2 = ((SharedPreferences) ps.b).getString("paid_3p_hash_key", null);
                    if (string != null && string2 != null && !string.equals(e(str, str2, string2))) {
                        return b(str, str2);
                    }
                }
            } catch (IllegalArgumentException unused) {
            }
            return new Ns();
        }
        boolean z2 = str != null;
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (jCurrentTimeMillis < 0) {
            throw new IllegalStateException(this.e.concat(": Invalid negative current timestamp. Updating PAID failed"));
        }
        String str4 = this.c;
        String str5 = this.d;
        long j2 = ((SharedPreferences) ps.b).getLong(z2 ? str5 : str4, -1L);
        if (j2 != -1) {
            if (jCurrentTimeMillis < j2) {
                ps.u(Long.valueOf(jCurrentTimeMillis), z2 ? str5 : str4);
            } else if (jCurrentTimeMillis >= j2 + j) {
                return b(str, str2);
            }
        }
        if (!z2) {
            str3 = this.a;
        }
        String string3 = ((SharedPreferences) ps.b).getString(str3, null);
        if (string3 == null && !z) {
            return b(str, str2);
        }
        if (z2) {
            str4 = str5;
        }
        return new Ns(string3, ((SharedPreferences) ps.b).getLong(str4, -1L));
    }

    public final Ns b(String str, String str2) throws IOException {
        if (str == null) {
            return c(UUID.randomUUID().toString(), false);
        }
        String string = UUID.randomUUID().toString();
        this.f.u(string, "paid_3p_hash_key");
        return c(e(str, str2, string), true);
    }

    public final Ns c(String str, boolean z) throws IOException {
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (jCurrentTimeMillis < 0) {
            throw new IllegalStateException(this.e.concat(": Invalid negative current timestamp. Updating PAID failed"));
        }
        String str2 = z ? this.d : this.c;
        Long lValueOf = Long.valueOf(jCurrentTimeMillis);
        Ps ps = this.f;
        ps.u(lValueOf, str2);
        ps.u(str, z ? this.b : this.a);
        return new Ns(str, jCurrentTimeMillis);
    }

    public final void d(boolean z) throws IOException {
        String str = z ? this.d : this.c;
        Ps ps = this.f;
        ps.v(str);
        ps.v(z ? this.b : this.a);
    }

    public final String e(String str, String str2, String str3) {
        if (str2 != null && str3 != null) {
            return UUID.nameUUIDFromBytes(android.support.v4.media.session.a.l(str, str2, str3).getBytes(StandardCharsets.UTF_8)).toString();
        }
        StringBuilder sb = new StringBuilder();
        sb.append(this.e);
        sb.append(": Invalid argument to generate PAIDv1 on 3p traffic, Ad ID is not null, package name is ");
        sb.append(str2 == null ? "null" : "not null");
        sb.append(", hashKey is ");
        sb.append(str3 == null ? "null" : "not null");
        throw new IllegalArgumentException(sb.toString());
    }
}
