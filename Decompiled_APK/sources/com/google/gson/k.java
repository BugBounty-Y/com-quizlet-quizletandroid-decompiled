package com.google.gson;

import androidx.work.impl.model.v;
import com.google.gson.reflect.TypeToken;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/* loaded from: classes2.dex */
public final class k {
    public final ThreadLocal a = new ThreadLocal();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final v c;
    public final com.google.gson.internal.bind.c d;
    public final List e;

    static {
        new TypeToken(Object.class);
    }

    public k(com.google.gson.internal.f fVar, HashMap map, ArrayList arrayList) {
        v vVar = new v(map);
        this.c = vVar;
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(com.google.gson.internal.bind.p.y);
        arrayList2.add(com.google.gson.internal.bind.h.c);
        arrayList2.add(fVar);
        arrayList2.addAll(arrayList);
        arrayList2.add(com.google.gson.internal.bind.p.o);
        arrayList2.add(com.google.gson.internal.bind.p.g);
        arrayList2.add(com.google.gson.internal.bind.p.d);
        arrayList2.add(com.google.gson.internal.bind.p.e);
        arrayList2.add(com.google.gson.internal.bind.p.f);
        com.google.gson.internal.bind.h hVar = com.google.gson.internal.bind.p.k;
        arrayList2.add(new com.google.gson.internal.bind.n(Long.TYPE, Long.class, hVar));
        arrayList2.add(new com.google.gson.internal.bind.n(Double.TYPE, Double.class, new h(0)));
        arrayList2.add(new com.google.gson.internal.bind.n(Float.TYPE, Float.class, new h(1)));
        arrayList2.add(com.google.gson.internal.bind.h.b);
        arrayList2.add(com.google.gson.internal.bind.p.h);
        arrayList2.add(com.google.gson.internal.bind.p.i);
        arrayList2.add(new com.google.gson.internal.bind.m(AtomicLong.class, new i(new i(hVar, 0), 2), 0));
        arrayList2.add(new com.google.gson.internal.bind.m(AtomicLongArray.class, new i(new i(hVar, 1), 2), 0));
        arrayList2.add(com.google.gson.internal.bind.p.j);
        arrayList2.add(com.google.gson.internal.bind.p.l);
        arrayList2.add(com.google.gson.internal.bind.p.p);
        arrayList2.add(com.google.gson.internal.bind.p.q);
        arrayList2.add(new com.google.gson.internal.bind.m(BigDecimal.class, com.google.gson.internal.bind.p.m, 0));
        arrayList2.add(new com.google.gson.internal.bind.m(BigInteger.class, com.google.gson.internal.bind.p.n, 0));
        arrayList2.add(com.google.gson.internal.bind.p.r);
        arrayList2.add(com.google.gson.internal.bind.p.s);
        arrayList2.add(com.google.gson.internal.bind.p.u);
        arrayList2.add(com.google.gson.internal.bind.p.v);
        arrayList2.add(com.google.gson.internal.bind.p.x);
        arrayList2.add(com.google.gson.internal.bind.p.t);
        arrayList2.add(com.google.gson.internal.bind.p.b);
        arrayList2.add(com.google.gson.internal.bind.d.c);
        arrayList2.add(com.google.gson.internal.bind.p.w);
        if (com.google.gson.internal.sql.b.a) {
            arrayList2.add(com.google.gson.internal.sql.b.c);
            arrayList2.add(com.google.gson.internal.sql.b.b);
            arrayList2.add(com.google.gson.internal.sql.b.d);
        }
        arrayList2.add(com.google.gson.internal.bind.b.d);
        arrayList2.add(com.google.gson.internal.bind.p.a);
        arrayList2.add(new com.google.gson.internal.bind.c(vVar, 0));
        arrayList2.add(new com.google.gson.internal.bind.c(vVar, 2));
        com.google.gson.internal.bind.c cVar = new com.google.gson.internal.bind.c(vVar, 1);
        this.d = cVar;
        arrayList2.add(cVar);
        arrayList2.add(com.google.gson.internal.bind.p.z);
        arrayList2.add(new com.google.gson.internal.bind.j(vVar, fVar, cVar));
        this.e = Collections.unmodifiableList(arrayList2);
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x005b A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.lang.String r5, java.lang.reflect.Type r6) {
        /*
            r4 = this;
            java.io.StringReader r0 = new java.io.StringReader
            r0.<init>(r5)
            com.google.gson.stream.a r5 = new com.google.gson.stream.a
            r5.<init>(r0)
            java.lang.String r0 = "AssertionError (GSON 2.8.9): "
            r1 = 1
            r5.b = r1
            r2 = 0
            r5.l0()     // Catch: java.lang.Throwable -> L23 java.lang.AssertionError -> L25 java.io.IOException -> L27 java.lang.IllegalStateException -> L29 java.io.EOFException -> L53
            com.google.gson.reflect.TypeToken r1 = new com.google.gson.reflect.TypeToken     // Catch: java.lang.Throwable -> L23 java.lang.AssertionError -> L25 java.io.IOException -> L27 java.lang.IllegalStateException -> L29 java.io.EOFException -> L2b
            r1.<init>(r6)     // Catch: java.lang.Throwable -> L23 java.lang.AssertionError -> L25 java.io.IOException -> L27 java.lang.IllegalStateException -> L29 java.io.EOFException -> L2b
            com.google.gson.q r6 = r4.b(r1)     // Catch: java.lang.Throwable -> L23 java.lang.AssertionError -> L25 java.io.IOException -> L27 java.lang.IllegalStateException -> L29 java.io.EOFException -> L2b
            java.lang.Object r6 = r6.a(r5)     // Catch: java.lang.Throwable -> L23 java.lang.AssertionError -> L25 java.io.IOException -> L27 java.lang.IllegalStateException -> L29 java.io.EOFException -> L2b
            r5.b = r2
            goto L59
        L23:
            r6 = move-exception
            goto L83
        L25:
            r6 = move-exception
            goto L2e
        L27:
            r6 = move-exception
            goto L47
        L29:
            r6 = move-exception
            goto L4d
        L2b:
            r6 = move-exception
            r1 = r2
            goto L54
        L2e:
            java.lang.AssertionError r1 = new java.lang.AssertionError     // Catch: java.lang.Throwable -> L23
            java.lang.StringBuilder r3 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L23
            r3.<init>(r0)     // Catch: java.lang.Throwable -> L23
            java.lang.String r0 = r6.getMessage()     // Catch: java.lang.Throwable -> L23
            r3.append(r0)     // Catch: java.lang.Throwable -> L23
            java.lang.String r0 = r3.toString()     // Catch: java.lang.Throwable -> L23
            r1.<init>(r0)     // Catch: java.lang.Throwable -> L23
            r1.initCause(r6)     // Catch: java.lang.Throwable -> L23
            throw r1     // Catch: java.lang.Throwable -> L23
        L47:
            com.google.gson.JsonSyntaxException r0 = new com.google.gson.JsonSyntaxException     // Catch: java.lang.Throwable -> L23
            r0.<init>(r6)     // Catch: java.lang.Throwable -> L23
            throw r0     // Catch: java.lang.Throwable -> L23
        L4d:
            com.google.gson.JsonSyntaxException r0 = new com.google.gson.JsonSyntaxException     // Catch: java.lang.Throwable -> L23
            r0.<init>(r6)     // Catch: java.lang.Throwable -> L23
            throw r0     // Catch: java.lang.Throwable -> L23
        L53:
            r6 = move-exception
        L54:
            if (r1 == 0) goto L7d
            r5.b = r2
            r6 = 0
        L59:
            if (r6 == 0) goto L7c
            int r5 = r5.l0()     // Catch: java.io.IOException -> L6c com.google.gson.stream.MalformedJsonException -> L6e
            r0 = 10
            if (r5 != r0) goto L64
            goto L7c
        L64:
            com.google.gson.JsonIOException r5 = new com.google.gson.JsonIOException     // Catch: java.io.IOException -> L6c com.google.gson.stream.MalformedJsonException -> L6e
            java.lang.String r6 = "JSON document was not fully consumed."
            r5.<init>(r6)     // Catch: java.io.IOException -> L6c com.google.gson.stream.MalformedJsonException -> L6e
            throw r5     // Catch: java.io.IOException -> L6c com.google.gson.stream.MalformedJsonException -> L6e
        L6c:
            r5 = move-exception
            goto L70
        L6e:
            r5 = move-exception
            goto L76
        L70:
            com.google.gson.JsonIOException r6 = new com.google.gson.JsonIOException
            r6.<init>(r5)
            throw r6
        L76:
            com.google.gson.JsonSyntaxException r6 = new com.google.gson.JsonSyntaxException
            r6.<init>(r5)
            throw r6
        L7c:
            return r6
        L7d:
            com.google.gson.JsonSyntaxException r0 = new com.google.gson.JsonSyntaxException     // Catch: java.lang.Throwable -> L23
            r0.<init>(r6)     // Catch: java.lang.Throwable -> L23
            throw r0     // Catch: java.lang.Throwable -> L23
        L83:
            r5.b = r2
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.gson.k.a(java.lang.String, java.lang.reflect.Type):java.lang.Object");
    }

    public final q b(TypeToken typeToken) {
        boolean z;
        ConcurrentHashMap concurrentHashMap = this.b;
        q qVar = (q) concurrentHashMap.get(typeToken);
        if (qVar != null) {
            return qVar;
        }
        ThreadLocal threadLocal = this.a;
        Map map = (Map) threadLocal.get();
        if (map == null) {
            map = new HashMap();
            threadLocal.set(map);
            z = true;
        } else {
            z = false;
        }
        j jVar = (j) map.get(typeToken);
        if (jVar != null) {
            return jVar;
        }
        try {
            j jVar2 = new j();
            map.put(typeToken, jVar2);
            Iterator it2 = this.e.iterator();
            while (it2.hasNext()) {
                q qVarB = ((r) it2.next()).b(this, typeToken);
                if (qVarB != null) {
                    if (jVar2.a != null) {
                        throw new AssertionError();
                    }
                    jVar2.a = qVarB;
                    concurrentHashMap.put(typeToken, qVarB);
                    map.remove(typeToken);
                    if (z) {
                        threadLocal.remove();
                    }
                    return qVarB;
                }
            }
            throw new IllegalArgumentException("GSON (2.8.9) cannot handle " + typeToken);
        } catch (Throwable th) {
            map.remove(typeToken);
            if (z) {
                threadLocal.remove();
            }
            throw th;
        }
    }

    public final q c(r rVar, TypeToken typeToken) {
        List<r> list = this.e;
        if (!list.contains(rVar)) {
            rVar = this.d;
        }
        boolean z = false;
        for (r rVar2 : list) {
            if (z) {
                q qVarB = rVar2.b(this, typeToken);
                if (qVarB != null) {
                    return qVarB;
                }
            } else if (rVar2 == rVar) {
                z = true;
            }
        }
        throw new IllegalArgumentException("GSON cannot serialize " + typeToken);
    }

    public final String toString() {
        return "{serializeNulls:false,factories:" + this.e + ",instanceCreators:" + this.c + "}";
    }
}
