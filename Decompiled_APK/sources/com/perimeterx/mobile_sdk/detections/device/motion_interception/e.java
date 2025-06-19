package com.perimeterx.mobile_sdk.detections.device.motion_interception;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ int j;
    public kotlinx.coroutines.sync.c k;
    public String l;
    public ArrayList m;
    public int n;
    public final /* synthetic */ String o;
    public final /* synthetic */ ArrayList p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(String str, ArrayList arrayList, h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.o = str;
        this.p = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        switch (this.j) {
            case 0:
                return new e(this.o, this.p, hVar, 0);
            default:
                return new e(this.o, this.p, hVar, 1);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        h hVar = (h) obj2;
        switch (this.j) {
            case 0:
                return new e(this.o, this.p, hVar, 0).invokeSuspend(Unit.a);
            default:
                return new e(this.o, this.p, hVar, 1).invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(6:(1:(1:29)(2:30|31))(3:32|(1:35)|46)|49|37|(1:39)(1:43)|45|46) */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00b8, code lost:
    
        r0 = kotlin.Unit.a;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            int r0 = r5.j
            switch(r0) {
                case 0: goto L66;
                default: goto L5;
            }
        L5:
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.n
            r2 = 1
            if (r1 == 0) goto L20
            if (r1 != r2) goto L18
            java.util.ArrayList r0 = r5.m
            java.lang.String r1 = r5.l
            kotlinx.coroutines.sync.c r2 = r5.k
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3a
        L18:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlinx.coroutines.sync.c r6 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.h
            r5.k = r6
            java.lang.String r1 = r5.o
            r5.l = r1
            java.util.ArrayList r3 = r5.p
            r5.m = r3
            r5.n = r2
            java.lang.Object r2 = r6.d(r5)
            if (r2 != r0) goto L38
            goto L61
        L38:
            r2 = r6
            r0 = r3
        L3a:
            r6 = 0
            com.quizlet.data.interactor.school.b r3 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.e     // Catch: java.lang.Throwable -> L5b
            java.lang.Object r4 = r3.c     // Catch: java.lang.Throwable -> L5b
            java.util.HashMap r4 = (java.util.HashMap) r4     // Catch: java.lang.Throwable -> L5b
            java.lang.Object r4 = r4.get(r1)     // Catch: java.lang.Throwable -> L5b
            java.util.ArrayList r4 = (java.util.ArrayList) r4     // Catch: java.lang.Throwable -> L5b
            if (r4 == 0) goto L5d
            r0.addAll(r4)     // Catch: java.lang.Throwable -> L5b
            java.lang.Object r0 = r3.c     // Catch: java.lang.Throwable -> L5b
            java.util.HashMap r0 = (java.util.HashMap) r0     // Catch: java.lang.Throwable -> L5b
            java.util.ArrayList r3 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L5b
            r3.<init>()     // Catch: java.lang.Throwable -> L5b
            r0.put(r1, r3)     // Catch: java.lang.Throwable -> L5b
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L5b
            goto L5e
        L5b:
            r0 = move-exception
            goto L62
        L5d:
            r0 = r6
        L5e:
            r2.f(r6)
        L61:
            return r0
        L62:
            r2.f(r6)
            throw r0
        L66:
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.n
            r2 = 1
            if (r1 == 0) goto L81
            if (r1 != r2) goto L79
            java.util.ArrayList r0 = r5.m
            java.lang.String r1 = r5.l
            kotlinx.coroutines.sync.c r2 = r5.k
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L9b
        L79:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L81:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlinx.coroutines.sync.c r6 = com.perimeterx.mobile_sdk.detections.device.motion_interception.g.i
            r5.k = r6
            java.lang.String r1 = r5.o
            r5.l = r1
            java.util.ArrayList r3 = r5.p
            r5.m = r3
            r5.n = r2
            java.lang.Object r2 = r6.d(r5)
            if (r2 != r0) goto L99
            goto Lbd
        L99:
            r2 = r6
            r0 = r3
        L9b:
            r6 = 0
            java.util.HashMap r3 = com.perimeterx.mobile_sdk.detections.device.motion_interception.g.h     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            java.lang.Object r4 = r3.get(r1)     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            java.util.ArrayList r4 = (java.util.ArrayList) r4     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            if (r4 == 0) goto Lb6
            r0.addAll(r4)     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            java.util.ArrayList r0 = new java.util.ArrayList     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            r0.<init>()     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            r3.put(r1, r0)     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> Lb4 java.lang.Exception -> Lb8
            goto Lba
        Lb4:
            r0 = move-exception
            goto Lbe
        Lb6:
            r0 = r6
            goto Lba
        Lb8:
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> Lb4
        Lba:
            r2.f(r6)
        Lbd:
            return r0
        Lbe:
            r2.f(r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.detections.device.motion_interception.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
