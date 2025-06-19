package com.facebook.appevents.iap;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.L;

/* loaded from: classes.dex */
public final class i implements InvocationHandler {
    public final /* synthetic */ int a;
    public final Serializable b;
    public final Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: Type inference failed for: r2v2, types: [java.io.Serializable, java.lang.Object[]] */
    public i(L l, Class cls) {
        this.a = 1;
        this.d = l;
        this.c = cls;
        this.b = new Object[0];
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0085 A[Catch: all -> 0x002b, Exception -> 0x0043, TryCatch #4 {all -> 0x002b, blocks: (B:5:0x000a, B:10:0x0025, B:15:0x0032, B:18:0x0038, B:19:0x0043, B:22:0x0055, B:23:0x0059, B:30:0x006a, B:37:0x007a, B:39:0x0085, B:43:0x008c, B:46:0x0098, B:48:0x00a8, B:49:0x00b2, B:36:0x0076, B:29:0x0066, B:51:0x00bc, B:54:0x00c7, B:68:0x00ea, B:69:0x00ee, B:57:0x00ce, B:64:0x00e4, B:60:0x00d8), top: B:82:0x000a, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0072 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x008c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x008b A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(java.lang.Object r10, java.lang.reflect.Method r11, java.lang.Object[] r12) {
        /*
            Method dump skipped, instructions count: 246
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.i.a(java.lang.Object, java.lang.reflect.Method, java.lang.Object[]):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:58:0x006c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // java.lang.reflect.InvocationHandler
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r7, java.lang.reflect.Method r8, java.lang.Object[] r9) {
        /*
            r6 = this;
            int r0 = r6.a
            switch(r0) {
                case 0: goto L90;
                default: goto L5;
            }
        L5:
            java.lang.Class r0 = r8.getDeclaringClass()
            java.lang.Class<java.lang.Object> r1 = java.lang.Object.class
            if (r0 != r1) goto L13
            java.lang.Object r7 = r8.invoke(r6, r9)
            goto L8d
        L13:
            if (r9 == 0) goto L17
        L15:
            r3 = r9
            goto L1c
        L17:
            java.io.Serializable r9 = r6.b
            java.lang.Object[] r9 = (java.lang.Object[]) r9
            goto L15
        L1c:
            retrofit2.a r9 = retrofit2.F.b
            boolean r0 = r9.e(r8)
            java.lang.Object r1 = r6.c
            java.lang.Class r1 = (java.lang.Class) r1
            if (r0 == 0) goto L2e
            java.lang.Object r7 = r9.d(r1, r7, r8, r3)
            goto L8d
        L2e:
            java.lang.Object r9 = r6.d
            retrofit2.L r9 = (retrofit2.L) r9
        L32:
            java.util.concurrent.ConcurrentHashMap r0 = r9.a
            java.lang.Object r0 = r0.get(r8)
            boolean r2 = r0 instanceof retrofit2.AbstractC5190o
            if (r2 == 0) goto L40
            retrofit2.o r0 = (retrofit2.AbstractC5190o) r0
        L3e:
            r8 = r0
            goto L7d
        L40:
            if (r0 != 0) goto L67
            java.lang.Object r2 = new java.lang.Object
            r2.<init>()
            monitor-enter(r2)
            java.util.concurrent.ConcurrentHashMap r0 = r9.a     // Catch: java.lang.Throwable -> L5b
            java.lang.Object r0 = r0.putIfAbsent(r8, r2)     // Catch: java.lang.Throwable -> L5b
            if (r0 != 0) goto L66
            retrofit2.o r0 = retrofit2.AbstractC5190o.b(r9, r1, r8)     // Catch: java.lang.Throwable -> L5e
            java.util.concurrent.ConcurrentHashMap r9 = r9.a     // Catch: java.lang.Throwable -> L5b
            r9.put(r8, r0)     // Catch: java.lang.Throwable -> L5b
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L5b
            goto L3e
        L5b:
            r0 = move-exception
            r7 = r0
            goto L69
        L5e:
            r0 = move-exception
            r7 = r0
            java.util.concurrent.ConcurrentHashMap r9 = r9.a     // Catch: java.lang.Throwable -> L5b
            r9.remove(r8)     // Catch: java.lang.Throwable -> L5b
            throw r7     // Catch: java.lang.Throwable -> L5b
        L66:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L5b
        L67:
            r2 = r0
            goto L6b
        L69:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L5b
            throw r7
        L6b:
            monitor-enter(r2)
            java.util.concurrent.ConcurrentHashMap r0 = r9.a     // Catch: java.lang.Throwable -> L76
            java.lang.Object r0 = r0.get(r8)     // Catch: java.lang.Throwable -> L76
            if (r0 != 0) goto L79
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L76
            goto L32
        L76:
            r0 = move-exception
            r7 = r0
            goto L8e
        L79:
            retrofit2.o r0 = (retrofit2.AbstractC5190o) r0     // Catch: java.lang.Throwable -> L76
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L76
            goto L3e
        L7d:
            retrofit2.u r0 = new retrofit2.u
            okhttp3.d r4 = r8.b
            retrofit2.k r5 = r8.c
            retrofit2.J r1 = r8.a
            r2 = r7
            r0.<init>(r1, r2, r3, r4, r5)
            java.lang.Object r7 = r8.a(r0, r3)
        L8d:
            return r7
        L8e:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L76
            throw r7
        L90:
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r6)
            r1 = 0
            if (r0 == 0) goto L98
            goto La3
        L98:
            r6.a(r7, r8, r9)     // Catch: java.lang.Throwable -> L9e
            kotlin.Unit r1 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L9e
            goto La3
        L9e:
            r0 = move-exception
            r7 = r0
            com.facebook.internal.instrument.crashshield.a.a(r6, r7)
        La3:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.i.invoke(java.lang.Object, java.lang.reflect.Method, java.lang.Object[]):java.lang.Object");
    }

    public i(l lVar, t skuType, Runnable completionHandler) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(skuType, "skuType");
        Intrinsics.checkNotNullParameter(completionHandler, "completionHandler");
        this.d = lVar;
        this.b = skuType;
        this.c = completionHandler;
    }
}
