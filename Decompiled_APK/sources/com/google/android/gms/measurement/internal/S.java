package com.google.android.gms.measurement.internal;

import android.text.TextUtils;
import androidx.collection.C0208f;
import androidx.collection.C0220s;

/* loaded from: classes2.dex */
public final class S extends C0220s {
    public final /* synthetic */ T h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(T t) {
        super(20);
        this.h = t;
    }

    @Override // androidx.collection.C0220s
    public final Object c(Object obj) throws Throwable {
        String str = (String) obj;
        com.google.android.gms.common.internal.u.e(str);
        T t = this.h;
        boolean zF0 = ((Y) t.b).g.f0(null, AbstractC3893t.n1);
        S s = t.k;
        if (zF0) {
            t.T();
            com.google.android.gms.common.internal.u.e(str);
            C3874j c3874j = t.c.c;
            r1.L(c3874j);
            com.quizlet.data.repository.user.a aVarR0 = c3874j.R0(str);
            if (aVarR0 == null) {
                return null;
            }
            I i = ((Y) t.b).i;
            Y.k(i);
            i.o.g("Populate EES config from database on cache miss. appId", str);
            t.b0(str, t.Y(str, (byte[]) aVarR0.b));
            return (com.google.android.gms.internal.measurement.D) s.n().get(str);
        }
        t.T();
        com.google.android.gms.common.internal.u.e(str);
        if (!TextUtils.isEmpty(str)) {
            C0208f c0208f = t.i;
            com.google.android.gms.internal.measurement.E0 e0 = (com.google.android.gms.internal.measurement.E0) c0208f.get(str);
            if (e0 != null && e0.n() != 0) {
                if (!c0208f.containsKey(str) || c0208f.get(str) == null) {
                    t.a0(str);
                } else {
                    t.b0(str, (com.google.android.gms.internal.measurement.E0) c0208f.get(str));
                }
                return (com.google.android.gms.internal.measurement.D) s.n().get(str);
            }
        }
        return null;
    }
}
