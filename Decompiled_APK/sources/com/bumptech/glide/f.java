package com.bumptech.glide;

import android.content.Context;
import com.facebook.appevents.u;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1548c;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.I;
import java.util.HashMap;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final HashMap a;

    public f(int i) {
        switch (i) {
            case 1:
                this.a = new HashMap();
                break;
            default:
                this.a = new HashMap();
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0024 A[Catch: all -> 0x0050, TryCatch #0 {, blocks: (B:3:0x0001, B:11:0x001a, B:12:0x001e, B:14:0x0024, B:16:0x0036, B:17:0x0040, B:19:0x0046, B:10:0x0017, B:7:0x0009), top: B:27:0x0001, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized void a(com.facebook.appevents.t r4) {
        /*
            r3 = this;
            monitor-enter(r3)
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r4)     // Catch: java.lang.Throwable -> L50
            r1 = 0
            if (r0 == 0) goto L9
            goto L1a
        L9:
            java.util.HashMap r0 = r4.a     // Catch: java.lang.Throwable -> L16
            java.util.Set r0 = r0.entrySet()     // Catch: java.lang.Throwable -> L16
            java.lang.String r2 = "events.entries"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)     // Catch: java.lang.Throwable -> L16
            r1 = r0
            goto L1a
        L16:
            r0 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r4, r0)     // Catch: java.lang.Throwable -> L50
        L1a:
            java.util.Iterator r4 = r1.iterator()     // Catch: java.lang.Throwable -> L50
        L1e:
            boolean r0 = r4.hasNext()     // Catch: java.lang.Throwable -> L50
            if (r0 == 0) goto L52
            java.lang.Object r0 = r4.next()     // Catch: java.lang.Throwable -> L50
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0     // Catch: java.lang.Throwable -> L50
            java.lang.Object r1 = r0.getKey()     // Catch: java.lang.Throwable -> L50
            com.facebook.appevents.b r1 = (com.facebook.appevents.b) r1     // Catch: java.lang.Throwable -> L50
            com.facebook.appevents.u r1 = r3.d(r1)     // Catch: java.lang.Throwable -> L50
            if (r1 == 0) goto L1e
            java.lang.Object r0 = r0.getValue()     // Catch: java.lang.Throwable -> L50
            java.util.List r0 = (java.util.List) r0     // Catch: java.lang.Throwable -> L50
            java.util.Iterator r0 = r0.iterator()     // Catch: java.lang.Throwable -> L50
        L40:
            boolean r2 = r0.hasNext()     // Catch: java.lang.Throwable -> L50
            if (r2 == 0) goto L1e
            java.lang.Object r2 = r0.next()     // Catch: java.lang.Throwable -> L50
            com.facebook.appevents.e r2 = (com.facebook.appevents.e) r2     // Catch: java.lang.Throwable -> L50
            r1.a(r2)     // Catch: java.lang.Throwable -> L50
            goto L40
        L50:
            r4 = move-exception
            goto L54
        L52:
            monitor-exit(r3)
            return
        L54:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L50
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.f.a(com.facebook.appevents.t):void");
    }

    public synchronized u b(com.facebook.appevents.b accessTokenAppIdPair) {
        Intrinsics.checkNotNullParameter(accessTokenAppIdPair, "accessTokenAppIdPair");
        return (u) this.a.get(accessTokenAppIdPair);
    }

    public synchronized int c() {
        int i;
        int size;
        i = 0;
        for (u uVar : this.a.values()) {
            synchronized (uVar) {
                if (!com.facebook.internal.instrument.crashshield.a.b(uVar)) {
                    try {
                        size = uVar.c.size();
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(uVar, th);
                    }
                }
                size = 0;
            }
            i += size;
        }
        return i;
    }

    public synchronized u d(com.facebook.appevents.b bVar) {
        Context contextA;
        C1548c c1548cB;
        u uVar = (u) this.a.get(bVar);
        if (uVar == null && (c1548cB = AbstractC1554i.b((contextA = o.a()))) != null) {
            uVar = new u(c1548cB, I.a(contextA));
        }
        if (uVar == null) {
            return null;
        }
        this.a.put(bVar, uVar);
        return uVar;
    }

    public synchronized Set e() {
        Set setKeySet;
        setKeySet = this.a.keySet();
        Intrinsics.checkNotNullExpressionValue(setKeySet, "stateMap.keys");
        return setKeySet;
    }
}
