package com.google.android.gms.common.api.internal;

import java.util.Arrays;

/* renamed from: com.google.android.gms.common.api.internal.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1643a {
    public final int a;
    public final com.quizlet.data.repository.activitycenter.b b;
    public final com.google.android.gms.common.api.b c;
    public final String d;

    public C1643a(com.quizlet.data.repository.activitycenter.b bVar, com.google.android.gms.common.api.b bVar2, String str) {
        this.b = bVar;
        this.c = bVar2;
        this.d = str;
        this.a = Arrays.hashCode(new Object[]{bVar, bVar2, str});
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C1643a)) {
            return false;
        }
        C1643a c1643a = (C1643a) obj;
        return com.google.android.gms.common.internal.u.l(this.b, c1643a.b) && com.google.android.gms.common.internal.u.l(this.c, c1643a.c) && com.google.android.gms.common.internal.u.l(this.d, c1643a.d);
    }

    public final int hashCode() {
        return this.a;
    }
}
