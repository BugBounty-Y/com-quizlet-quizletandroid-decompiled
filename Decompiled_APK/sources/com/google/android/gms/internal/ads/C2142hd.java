package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.measurement.internal.zzbf;
import java.io.Serializable;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.hd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2142hd {
    public final /* synthetic */ int a;
    public long b;
    public long c;
    public Object d;
    public Object e;
    public final Serializable f;
    public final Object g;

    public C2142hd() {
        this.a = 0;
        this.f = new AtomicBoolean(false);
        this.g = new AtomicBoolean(false);
        this.b = -1L;
        this.c = -1L;
    }

    public C2142hd a(com.google.android.gms.measurement.internal.Y y, long j) {
        return new C2142hd(y, (String) this.f, (String) this.d, (String) this.e, this.b, j, (zzbf) this.g);
    }

    public void b(C2227jd c2227jd, Hk hk) {
        if (((AtomicBoolean) this.f).getAndSet(true)) {
            return;
        }
        this.d = c2227jd;
        this.e = hk;
        C2601s7 c2601s7 = AbstractC2773w7.td;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.b = ((Long) rVar.c.a(c2601s7)).longValue();
        this.c = ((Long) rVar.c.a(AbstractC2773w7.ud)).longValue();
    }

    public String toString() {
        switch (this.a) {
            case 1:
                String string = ((zzbf) this.g).toString();
                StringBuilder sb = new StringBuilder("Event{appId='");
                sb.append((String) this.d);
                sb.append("', name='");
                return androidx.compose.ui.node.B.j(sb, (String) this.e, "', params=", string, "}");
            default:
                return super.toString();
        }
    }

    public C2142hd(com.google.android.gms.measurement.internal.Y y, String str, String str2, String str3, long j, long j2, Bundle bundle) {
        zzbf zzbfVar;
        this.a = 1;
        com.google.android.gms.common.internal.u.e(str2);
        com.google.android.gms.common.internal.u.e(str3);
        this.d = str2;
        this.e = str3;
        this.f = true == TextUtils.isEmpty(str) ? null : str;
        this.b = j;
        this.c = j2;
        if (j2 != 0 && j2 > j) {
            com.google.android.gms.measurement.internal.I i = y.i;
            com.google.android.gms.measurement.internal.Y.k(i);
            i.j.g("Event created with reverse previous/current timestamps. appId", com.google.android.gms.measurement.internal.I.a0(str2));
        }
        if (bundle != null && !bundle.isEmpty()) {
            Bundle bundle2 = new Bundle(bundle);
            Iterator<String> it2 = bundle2.keySet().iterator();
            while (it2.hasNext()) {
                String next = it2.next();
                if (next == null) {
                    com.google.android.gms.measurement.internal.I i2 = y.i;
                    com.google.android.gms.measurement.internal.Y.k(i2);
                    i2.g.f("Param name can't be null");
                    it2.remove();
                } else {
                    com.google.android.gms.measurement.internal.x1 x1Var = y.l;
                    com.google.android.gms.measurement.internal.Y.h(x1Var);
                    Object objY = x1Var.Y(bundle2.get(next), next);
                    if (objY == null) {
                        com.google.android.gms.measurement.internal.I i3 = y.i;
                        com.google.android.gms.measurement.internal.Y.k(i3);
                        i3.j.g("Param value can't be null", y.m.e(next));
                        it2.remove();
                    } else {
                        com.google.android.gms.measurement.internal.x1 x1Var2 = y.l;
                        com.google.android.gms.measurement.internal.Y.h(x1Var2);
                        x1Var2.m0(bundle2, next, objY);
                    }
                }
            }
            zzbfVar = new zzbf(bundle2);
        } else {
            zzbfVar = new zzbf(new Bundle());
        }
        this.g = zzbfVar;
    }

    public C2142hd(com.google.android.gms.measurement.internal.Y y, String str, String str2, String str3, long j, long j2, zzbf zzbfVar) {
        this.a = 1;
        com.google.android.gms.common.internal.u.e(str2);
        com.google.android.gms.common.internal.u.e(str3);
        com.google.android.gms.common.internal.u.h(zzbfVar);
        this.d = str2;
        this.e = str3;
        this.f = true == TextUtils.isEmpty(str) ? null : str;
        this.b = j;
        this.c = j2;
        if (j2 != 0 && j2 > j) {
            com.google.android.gms.measurement.internal.I i = y.i;
            com.google.android.gms.measurement.internal.Y.k(i);
            i.j.h("Event created with reverse previous/current timestamps. appId, name", com.google.android.gms.measurement.internal.I.a0(str2), com.google.android.gms.measurement.internal.I.a0(str3));
        }
        this.g = zzbfVar;
    }
}
