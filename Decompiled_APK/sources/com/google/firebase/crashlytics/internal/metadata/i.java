package com.google.firebase.crashlytics.internal.metadata;

/* loaded from: classes2.dex */
public final class i {
    public static final i c = new i(0, 0);
    public final int a;
    public final int b;

    public i(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(i.class.getSimpleName());
        sb.append("[position = ");
        sb.append(this.a);
        sb.append(", length = ");
        return android.support.v4.media.session.a.r(sb, this.b, "]");
    }
}
