package com.google.firebase.sessions.api;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public static final c a = new c();
    public static final Map b = Collections.synchronizedMap(new LinkedHashMap());

    public static a a(d dVar) {
        Map dependencies = b;
        Intrinsics.checkNotNullExpressionValue(dependencies, "dependencies");
        Object obj = dependencies.get(dVar);
        if (obj != null) {
            Intrinsics.checkNotNullExpressionValue(obj, "dependencies.getOrElse(s…load time.\"\n      )\n    }");
            return (a) obj;
        }
        throw new IllegalStateException("Cannot get dependency " + dVar + ". Dependencies should be added at class load time.");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00b2 A[Catch: all -> 0x00cb, TRY_ENTER, TryCatch #0 {all -> 0x00cb, blocks: (B:22:0x009b, B:25:0x00b2, B:26:0x00ca), top: B:31:0x009b }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00d2 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:20:0x0099 -> B:21:0x009a). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10 = this;
            boolean r0 = r11 instanceof com.google.firebase.sessions.api.b
            if (r0 == 0) goto L13
            r0 = r11
            com.google.firebase.sessions.api.b r0 = (com.google.firebase.sessions.api.b) r0
            int r1 = r0.r
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.r = r1
            goto L18
        L13:
            com.google.firebase.sessions.api.b r0 = new com.google.firebase.sessions.api.b
            r0.<init>(r10, r11)
        L18:
            java.lang.Object r11 = r0.p
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.r
            r3 = 1
            if (r2 == 0) goto L3f
            if (r2 != r3) goto L37
            java.lang.Object r2 = r0.o
            java.util.Map r4 = r0.n
            java.util.Map r4 = (java.util.Map) r4
            kotlinx.coroutines.sync.a r5 = r0.m
            com.google.firebase.sessions.api.d r6 = r0.l
            java.util.Iterator r7 = r0.k
            java.util.Map r8 = r0.j
            java.util.Map r8 = (java.util.Map) r8
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L9a
        L37:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.util.Map r11 = com.google.firebase.sessions.api.c.b
            java.lang.String r2 = "dependencies"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r11, r2)
            java.util.LinkedHashMap r2 = new java.util.LinkedHashMap
            int r4 = r11.size()
            int r4 = kotlin.collections.U.a(r4)
            r2.<init>(r4)
            java.util.Set r11 = r11.entrySet()
            java.lang.Iterable r11 = (java.lang.Iterable) r11
            java.util.Iterator r11 = r11.iterator()
            r7 = r11
            r4 = r2
        L62:
            boolean r11 = r7.hasNext()
            if (r11 == 0) goto Ld2
            java.lang.Object r11 = r7.next()
            java.util.Map$Entry r11 = (java.util.Map.Entry) r11
            java.lang.Object r2 = r11.getKey()
            java.lang.Object r5 = r11.getKey()
            r6 = r5
            com.google.firebase.sessions.api.d r6 = (com.google.firebase.sessions.api.d) r6
            java.lang.Object r11 = r11.getValue()
            com.google.firebase.sessions.api.a r11 = (com.google.firebase.sessions.api.a) r11
            kotlinx.coroutines.sync.c r5 = r11.a
            r11 = r4
            java.util.Map r11 = (java.util.Map) r11
            r0.j = r11
            r0.k = r7
            r0.l = r6
            r0.m = r5
            r0.n = r11
            r0.o = r2
            r0.r = r3
            java.lang.Object r11 = r5.d(r0)
            if (r11 != r1) goto L99
            return r1
        L99:
            r8 = r4
        L9a:
            r11 = 0
            java.lang.String r9 = "subscriberName"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r9)     // Catch: java.lang.Throwable -> Lcb
            com.google.firebase.sessions.api.a r9 = a(r6)     // Catch: java.lang.Throwable -> Lcb
            com.google.firebase.crashlytics.internal.common.h r9 = r9.b     // Catch: java.lang.Throwable -> Lcb
            if (r9 == 0) goto Lb2
            kotlinx.coroutines.sync.c r5 = (kotlinx.coroutines.sync.c) r5
            r5.f(r11)
            r4.put(r2, r9)
            r4 = r8
            goto L62
        Lb2:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> Lcb
            java.lang.StringBuilder r1 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> Lcb
            java.lang.String r2 = "Subscriber "
            r1.<init>(r2)     // Catch: java.lang.Throwable -> Lcb
            r1.append(r6)     // Catch: java.lang.Throwable -> Lcb
            java.lang.String r2 = " has not been registered."
            r1.append(r2)     // Catch: java.lang.Throwable -> Lcb
            java.lang.String r1 = r1.toString()     // Catch: java.lang.Throwable -> Lcb
            r0.<init>(r1)     // Catch: java.lang.Throwable -> Lcb
            throw r0     // Catch: java.lang.Throwable -> Lcb
        Lcb:
            r0 = move-exception
            kotlinx.coroutines.sync.c r5 = (kotlinx.coroutines.sync.c) r5
            r5.f(r11)
            throw r0
        Ld2:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.api.c.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
