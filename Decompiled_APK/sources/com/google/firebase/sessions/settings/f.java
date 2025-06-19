package com.google.firebase.sessions.settings;

import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ c m;
    public final /* synthetic */ d n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(g gVar, Map map, c cVar, d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = map;
        this.m = cVar;
        this.n = dVar;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = this.m;
        d dVar = this.n;
        return new f(this.k, this.l, cVar, dVar, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x00c2, code lost:
    
        if (r2.invoke(r9, r8) == r0) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00d5, code lost:
    
        if (r2.invoke(r1, r8) != r0) goto L37;
     */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.io.IOException {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            com.google.firebase.sessions.settings.d r2 = r8.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L26
            if (r1 == r5) goto L1e
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto Ld8
        L16:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L23
            goto Ld8
        L23:
            r9 = move-exception
            goto Lc5
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.google.firebase.sessions.settings.g r9 = r8.k     // Catch: java.lang.Exception -> L23
            java.net.URL r9 = com.google.firebase.sessions.settings.g.a(r9)     // Catch: java.lang.Exception -> L23
            java.net.URLConnection r9 = r9.openConnection()     // Catch: java.lang.Exception -> L23
            java.lang.String r1 = "null cannot be cast to non-null type javax.net.ssl.HttpsURLConnection"
            kotlin.jvm.internal.Intrinsics.e(r9, r1)     // Catch: java.lang.Exception -> L23
            javax.net.ssl.HttpsURLConnection r9 = (javax.net.ssl.HttpsURLConnection) r9     // Catch: java.lang.Exception -> L23
            java.lang.String r1 = "GET"
            r9.setRequestMethod(r1)     // Catch: java.lang.Exception -> L23
            java.lang.String r1 = "Accept"
            java.lang.String r6 = "application/json"
            r9.setRequestProperty(r1, r6)     // Catch: java.lang.Exception -> L23
            java.lang.Object r1 = r8.l     // Catch: java.lang.Exception -> L23
            java.util.Set r1 = r1.entrySet()     // Catch: java.lang.Exception -> L23
            java.util.Iterator r1 = r1.iterator()     // Catch: java.lang.Exception -> L23
        L50:
            boolean r6 = r1.hasNext()     // Catch: java.lang.Exception -> L23
            if (r6 == 0) goto L6c
            java.lang.Object r6 = r1.next()     // Catch: java.lang.Exception -> L23
            java.util.Map$Entry r6 = (java.util.Map.Entry) r6     // Catch: java.lang.Exception -> L23
            java.lang.Object r7 = r6.getKey()     // Catch: java.lang.Exception -> L23
            java.lang.String r7 = (java.lang.String) r7     // Catch: java.lang.Exception -> L23
            java.lang.Object r6 = r6.getValue()     // Catch: java.lang.Exception -> L23
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Exception -> L23
            r9.setRequestProperty(r7, r6)     // Catch: java.lang.Exception -> L23
            goto L50
        L6c:
            int r1 = r9.getResponseCode()     // Catch: java.lang.Exception -> L23
            r6 = 200(0xc8, float:2.8E-43)
            if (r1 != r6) goto Lab
            java.io.InputStream r9 = r9.getInputStream()     // Catch: java.lang.Exception -> L23
            java.io.BufferedReader r1 = new java.io.BufferedReader     // Catch: java.lang.Exception -> L23
            java.io.InputStreamReader r4 = new java.io.InputStreamReader     // Catch: java.lang.Exception -> L23
            r4.<init>(r9)     // Catch: java.lang.Exception -> L23
            r1.<init>(r4)     // Catch: java.lang.Exception -> L23
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L23
            r4.<init>()     // Catch: java.lang.Exception -> L23
        L87:
            java.lang.String r6 = r1.readLine()     // Catch: java.lang.Exception -> L23
            if (r6 == 0) goto L91
            r4.append(r6)     // Catch: java.lang.Exception -> L23
            goto L87
        L91:
            r1.close()     // Catch: java.lang.Exception -> L23
            r9.close()     // Catch: java.lang.Exception -> L23
            org.json.JSONObject r9 = new org.json.JSONObject     // Catch: java.lang.Exception -> L23
            java.lang.String r1 = r4.toString()     // Catch: java.lang.Exception -> L23
            r9.<init>(r1)     // Catch: java.lang.Exception -> L23
            com.google.firebase.sessions.settings.c r1 = r8.m     // Catch: java.lang.Exception -> L23
            r8.j = r5     // Catch: java.lang.Exception -> L23
            java.lang.Object r9 = r1.invoke(r9, r8)     // Catch: java.lang.Exception -> L23
            if (r9 != r0) goto Ld8
            goto Ld7
        Lab:
            java.lang.StringBuilder r9 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L23
            r9.<init>()     // Catch: java.lang.Exception -> L23
            java.lang.String r5 = "Bad response code: "
            r9.append(r5)     // Catch: java.lang.Exception -> L23
            r9.append(r1)     // Catch: java.lang.Exception -> L23
            java.lang.String r9 = r9.toString()     // Catch: java.lang.Exception -> L23
            r8.j = r4     // Catch: java.lang.Exception -> L23
            java.lang.Object r9 = r2.invoke(r9, r8)     // Catch: java.lang.Exception -> L23
            if (r9 != r0) goto Ld8
            goto Ld7
        Lc5:
            java.lang.String r1 = r9.getMessage()
            if (r1 != 0) goto Lcf
            java.lang.String r1 = r9.toString()
        Lcf:
            r8.j = r3
            java.lang.Object r9 = r2.invoke(r1, r8)
            if (r9 != r0) goto Ld8
        Ld7:
            return r0
        Ld8:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.settings.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
