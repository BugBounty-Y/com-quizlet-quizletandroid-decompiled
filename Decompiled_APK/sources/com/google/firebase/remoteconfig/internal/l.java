package com.google.firebase.remoteconfig.internal;

/* loaded from: classes2.dex */
public final class l implements com.google.firebase.remoteconfig.c {
    public final String a;
    public final int b;

    public l(String str, int i) {
        this.a = str;
        this.b = i;
    }

    public final boolean a() {
        if (this.b == 0) {
            return false;
        }
        String strTrim = d().trim();
        if (f.e.matcher(strTrim).matches()) {
            return true;
        }
        if (f.f.matcher(strTrim).matches()) {
            return false;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.B("[Value: ", strTrim, "] cannot be converted to a boolean."));
    }

    public final double b() {
        if (this.b == 0) {
            return 0.0d;
        }
        String strTrim = d().trim();
        try {
            return Double.valueOf(strTrim).doubleValue();
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("[Value: ", strTrim, "] cannot be converted to a double."), e);
        }
    }

    public final long c() {
        if (this.b == 0) {
            return 0L;
        }
        String strTrim = d().trim();
        try {
            return Long.valueOf(strTrim).longValue();
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("[Value: ", strTrim, "] cannot be converted to a long."), e);
        }
    }

    public final String d() {
        return this.b == 0 ? "" : this.a;
    }
}
