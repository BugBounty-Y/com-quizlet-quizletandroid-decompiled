package com.quizlet.data.repository.metering;

import com.quizlet.data.model.InterfaceC4176w0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Exception j;
    public int k;
    public final /* synthetic */ j l;
    public final /* synthetic */ InterfaceC4176w0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, InterfaceC4176w0 interfaceC4176w0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = jVar;
        this.m = interfaceC4176w0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x006f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0070  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) throws java.lang.Exception {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.k
            com.quizlet.data.model.w0 r2 = r10.m
            r3 = 2
            r4 = 1
            com.quizlet.data.repository.metering.j r5 = r10.l
            r6 = 0
            if (r1 == 0) goto L27
            if (r1 == r4) goto L21
            if (r1 != r3) goto L19
            java.lang.Exception r0 = r10.j
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Exception -> L17
            goto L6b
        L17:
            r11 = move-exception
            goto L71
        L19:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Exception -> L25
            goto L37
        L25:
            r11 = move-exception
            goto L3d
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Object r11 = r5.a     // Catch: java.lang.Exception -> L25
            com.quizlet.data.repository.folderwithcreator.e r11 = (com.quizlet.data.repository.folderwithcreator.e) r11     // Catch: java.lang.Exception -> L25
            r10.k = r4     // Catch: java.lang.Exception -> L25
            java.lang.Object r11 = r11.s(r2, r10)     // Catch: java.lang.Exception -> L25
            if (r11 != r0) goto L37
            goto L68
        L37:
            com.quizlet.data.model.w0 r11 = (com.quizlet.data.model.InterfaceC4176w0) r11     // Catch: java.lang.Exception -> L25
            r9 = r6
            r6 = r11
            r11 = r9
            goto L56
        L3d:
            java.lang.Object r1 = r5.c
            org.slf4j.b r1 = (org.slf4j.b) r1
            java.lang.String r4 = r11.getMessage()
            java.lang.StringBuilder r7 = new java.lang.StringBuilder
            java.lang.String r8 = "Remote error trying to save MeteringInfo: "
            r7.<init>(r8)
            r7.append(r4)
            java.lang.String r4 = r7.toString()
            r1.m(r4)
        L56:
            java.lang.Object r1 = r5.b     // Catch: java.lang.Exception -> L17
            com.quizlet.data.repository.folderset.c r1 = (com.quizlet.data.repository.folderset.c) r1     // Catch: java.lang.Exception -> L17
            if (r6 != 0) goto L5d
            goto L5e
        L5d:
            r2 = r6
        L5e:
            r10.j = r11     // Catch: java.lang.Exception -> L17
            r10.k = r3     // Catch: java.lang.Exception -> L17
            java.lang.Object r1 = r1.z(r2, r10)     // Catch: java.lang.Exception -> L17
            if (r1 != r0) goto L69
        L68:
            return r0
        L69:
            r0 = r11
            r11 = r1
        L6b:
            com.quizlet.data.model.w0 r11 = (com.quizlet.data.model.InterfaceC4176w0) r11     // Catch: java.lang.Exception -> L17
            if (r0 != 0) goto L70
            return r11
        L70:
            throw r0
        L71:
            java.lang.Object r0 = r5.c
            org.slf4j.b r0 = (org.slf4j.b) r0
            java.lang.String r1 = r11.getMessage()
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            java.lang.String r3 = "Local error trying to save MeteringInfo: "
            r2.<init>(r3)
            r2.append(r1)
            java.lang.String r1 = r2.toString()
            r0.m(r1)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.metering.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
