package com.google.android.gms.internal.ads;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class Jk implements Mq {
    public final Ek b;
    public final com.google.android.gms.common.util.a c;
    public final HashMap a = new HashMap();
    public final HashMap d = new HashMap();

    public Jk(Ek ek, Set set, com.google.android.gms.common.util.a aVar) {
        this.b = ek;
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            Ik ik = (Ik) it2.next();
            HashMap map = this.d;
            ik.getClass();
            map.put(Jq.RENDERER, ik);
        }
        this.c = aVar;
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void A(String str) {
    }

    public final void a(Jq jq, boolean z) {
        Ik ik = (Ik) this.d.get(jq);
        if (ik == null) {
            return;
        }
        String str = true != z ? "f." : "s.";
        HashMap map = this.a;
        Jq jq2 = ik.b;
        if (map.containsKey(jq2)) {
            long jElapsedRealtime = this.c.elapsedRealtime() - ((Long) map.get(jq2)).longValue();
            this.b.a.put("label.".concat(ik.a), str + jElapsedRealtime);
        }
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void c(Jq jq, String str) {
        this.a.put(jq, Long.valueOf(this.c.elapsedRealtime()));
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void d(Jq jq, String str, Throwable th) {
        HashMap map = this.a;
        if (map.containsKey(jq)) {
            long jElapsedRealtime = this.c.elapsedRealtime() - ((Long) map.get(jq)).longValue();
            String strValueOf = String.valueOf(str);
            this.b.a.put("task.".concat(strValueOf), "f.".concat(String.valueOf(Long.toString(jElapsedRealtime))));
        }
        if (this.d.containsKey(jq)) {
            a(jq, false);
        }
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void r(Jq jq, String str) {
        HashMap map = this.a;
        if (map.containsKey(jq)) {
            long jElapsedRealtime = this.c.elapsedRealtime() - ((Long) map.get(jq)).longValue();
            String strValueOf = String.valueOf(str);
            this.b.a.put("task.".concat(strValueOf), "s.".concat(String.valueOf(Long.toString(jElapsedRealtime))));
        }
        if (this.d.containsKey(jq)) {
            a(jq, true);
        }
    }
}
