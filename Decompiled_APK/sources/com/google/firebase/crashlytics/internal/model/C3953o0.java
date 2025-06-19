package com.google.firebase.crashlytics.internal.model;

import android.os.Build;

/* renamed from: com.google.firebase.crashlytics.internal.model.o0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3953o0 {
    public final boolean a;

    public C3953o0(boolean z) {
        String str = Build.VERSION.RELEASE;
        String str2 = Build.VERSION.CODENAME;
        if (str == null) {
            throw new NullPointerException("Null osRelease");
        }
        if (str2 == null) {
            throw new NullPointerException("Null osCodeName");
        }
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C3953o0)) {
            return false;
        }
        C3953o0 c3953o0 = (C3953o0) obj;
        c3953o0.getClass();
        String str = Build.VERSION.RELEASE;
        if (!str.equals(str)) {
            return false;
        }
        String str2 = Build.VERSION.CODENAME;
        return str2.equals(str2) && this.a == c3953o0.a;
    }

    public final int hashCode() {
        return ((((Build.VERSION.RELEASE.hashCode() ^ 1000003) * 1000003) ^ Build.VERSION.CODENAME.hashCode()) * 1000003) ^ (this.a ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OsData{osRelease=");
        sb.append(Build.VERSION.RELEASE);
        sb.append(", osCodeName=");
        sb.append(Build.VERSION.CODENAME);
        sb.append(", isRooted=");
        return android.support.v4.media.session.a.o("}", sb, this.a);
    }
}
