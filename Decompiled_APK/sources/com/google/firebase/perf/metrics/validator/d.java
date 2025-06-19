package com.google.firebase.perf.metrics.validator;

import com.google.firebase.perf.v1.E;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class d extends e {
    public static final com.google.firebase.perf.logging.a b = com.google.firebase.perf.logging.a.d();
    public final E a;

    public d(E e) {
        this.a = e;
    }

    public static boolean d(E e, int i) {
        if (e != null) {
            com.google.firebase.perf.logging.a aVar = b;
            if (i > 1) {
                aVar.f("Exceed MAX_SUBTRACE_DEEP:1");
                return false;
            }
            for (Map.Entry entry : e.H().entrySet()) {
                String str = (String) entry.getKey();
                if (str != null) {
                    String strTrim = str.trim();
                    if (strTrim.isEmpty()) {
                        aVar.f("counterId is empty");
                    } else if (strTrim.length() > 100) {
                        aVar.f("counterId exceeded max length 100");
                    } else if (((Long) entry.getValue()) == null) {
                        aVar.f("invalid CounterValue:" + entry.getValue());
                        return false;
                    }
                }
                aVar.f("invalid CounterId:" + ((String) entry.getKey()));
                return false;
            }
            Iterator it2 = e.N().iterator();
            while (it2.hasNext()) {
                if (!d((E) it2.next(), i + 1)) {
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x009c, code lost:
    
        r7 = r7.I().entrySet().iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00ac, code lost:
    
        if (r7.hasNext() == false) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00ae, code lost:
    
        r8 = (java.util.Map.Entry) r7.next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00b4, code lost:
    
        com.google.firebase.perf.metrics.validator.e.b((java.lang.String) r8.getKey(), (java.lang.String) r8.getValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00c4, code lost:
    
        r7 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c5, code lost:
    
        r0.f(r7.getLocalizedMessage());
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00cd, code lost:
    
        return true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean e(com.google.firebase.perf.v1.E r7, int r8) {
        /*
            com.google.firebase.perf.logging.a r0 = com.google.firebase.perf.metrics.validator.d.b
            r1 = 0
            if (r7 != 0) goto Lb
            java.lang.String r7 = "TraceMetric is null"
            r0.f(r7)
            return r1
        Lb:
            r2 = 1
            if (r8 <= r2) goto L14
            java.lang.String r7 = "Exceed MAX_SUBTRACE_DEEP:1"
            r0.f(r7)
            return r1
        L14:
            java.lang.String r3 = r7.L()
            if (r3 != 0) goto L1c
            goto Le4
        L1c:
            java.lang.String r3 = r3.trim()
            boolean r4 = r3.isEmpty()
            if (r4 != 0) goto Le4
            int r3 = r3.length()
            r4 = 100
            if (r3 > r4) goto Le4
            long r3 = r7.K()
            r5 = 0
            int r3 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r3 <= 0) goto Lce
            boolean r3 = r7.O()
            if (r3 != 0) goto L44
            java.lang.String r7 = "clientStartTimeUs is null."
            r0.f(r7)
            return r1
        L44:
            java.lang.String r3 = r7.L()
            java.lang.String r4 = "_st_"
            boolean r3 = r3.startsWith(r4)
            if (r3 == 0) goto L7f
            java.util.Map r3 = r7.H()
            java.lang.String r4 = "_fr_tot"
            java.lang.Object r3 = r3.get(r4)
            java.lang.Long r3 = (java.lang.Long) r3
            if (r3 == 0) goto L69
            java.lang.Long r4 = java.lang.Long.valueOf(r5)
            int r3 = r3.compareTo(r4)
            if (r3 <= 0) goto L69
            goto L7f
        L69:
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            java.lang.String r2 = "non-positive totalFrames in screen trace "
            r8.<init>(r2)
            java.lang.String r7 = r7.L()
            r8.append(r7)
            java.lang.String r7 = r8.toString()
            r0.f(r7)
            return r1
        L7f:
            com.google.protobuf.B r3 = r7.N()
            java.util.Iterator r3 = r3.iterator()
        L87:
            boolean r4 = r3.hasNext()
            if (r4 == 0) goto L9c
            java.lang.Object r4 = r3.next()
            com.google.firebase.perf.v1.E r4 = (com.google.firebase.perf.v1.E) r4
            int r5 = r8 + 1
            boolean r4 = e(r4, r5)
            if (r4 != 0) goto L87
            goto Lcc
        L9c:
            java.util.Map r7 = r7.I()
            java.util.Set r7 = r7.entrySet()
            java.util.Iterator r7 = r7.iterator()
        La8:
            boolean r8 = r7.hasNext()
            if (r8 == 0) goto Lcd
            java.lang.Object r8 = r7.next()
            java.util.Map$Entry r8 = (java.util.Map.Entry) r8
            java.lang.Object r3 = r8.getKey()     // Catch: java.lang.IllegalArgumentException -> Lc4
            java.lang.String r3 = (java.lang.String) r3     // Catch: java.lang.IllegalArgumentException -> Lc4
            java.lang.Object r8 = r8.getValue()     // Catch: java.lang.IllegalArgumentException -> Lc4
            java.lang.String r8 = (java.lang.String) r8     // Catch: java.lang.IllegalArgumentException -> Lc4
            com.google.firebase.perf.metrics.validator.e.b(r3, r8)     // Catch: java.lang.IllegalArgumentException -> Lc4
            goto La8
        Lc4:
            r7 = move-exception
            java.lang.String r7 = r7.getLocalizedMessage()
            r0.f(r7)
        Lcc:
            return r1
        Lcd:
            return r2
        Lce:
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            java.lang.String r2 = "invalid TraceDuration:"
            r8.<init>(r2)
            long r2 = r7.K()
            r8.append(r2)
            java.lang.String r7 = r8.toString()
            r0.f(r7)
            return r1
        Le4:
            java.lang.StringBuilder r8 = new java.lang.StringBuilder
            java.lang.String r2 = "invalid TraceId:"
            r8.<init>(r2)
            java.lang.String r7 = r7.L()
            r8.append(r7)
            java.lang.String r7 = r8.toString()
            r0.f(r7)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.metrics.validator.d.e(com.google.firebase.perf.v1.E, int):boolean");
    }

    @Override // com.google.firebase.perf.metrics.validator.e
    public final boolean a() {
        E e = this.a;
        boolean zE = e(e, 0);
        com.google.firebase.perf.logging.a aVar = b;
        if (!zE) {
            aVar.f("Invalid Trace:" + e.L());
            return false;
        }
        if (e.G() <= 0) {
            Iterator it2 = e.N().iterator();
            while (it2.hasNext()) {
                if (((E) it2.next()).G() > 0) {
                }
            }
            return true;
        }
        if (d(e, 0)) {
            return true;
        }
        aVar.f("Invalid Counters for Trace:" + e.L());
        return false;
    }
}
