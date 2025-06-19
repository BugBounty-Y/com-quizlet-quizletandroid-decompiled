package com.braze.dispatch;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public long a;
    public int b;
    public /* synthetic */ Object c;
    public final /* synthetic */ f d;
    public final /* synthetic */ long e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.d = fVar;
        this.e = j;
    }

    public static final String a() {
        return "Requesting data flush from automatic sync policy";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.d, this.e, hVar);
        eVar.c = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0061, code lost:
    
        if (kotlinx.coroutines.E.n(r3, r13) == r0) goto L19;
     */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0086  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0061 -> B:20:0x0064). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) {
        /*
            r13 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r13.b
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L28
            if (r1 == r3) goto L1e
            if (r1 != r2) goto L16
            long r3 = r13.a
            java.lang.Object r1 = r13.c
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L64
        L16:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L1e:
            long r3 = r13.a
            java.lang.Object r1 = r13.c
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L44
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r13.c
            r1 = r14
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            com.braze.dispatch.f r14 = r13.d
            long r4 = r14.g
            long r6 = r13.e
            r13.c = r1
            r13.a = r4
            r13.b = r3
            java.lang.Object r14 = kotlinx.coroutines.E.n(r6, r13)
            if (r14 != r0) goto L43
            goto L63
        L43:
            r3 = r4
        L44:
            com.braze.Braze$Companion r14 = com.braze.Braze.Companion
            com.braze.dispatch.f r5 = r13.d
            android.content.Context r5 = r5.a
            com.braze.Braze r14 = r14.getInstance(r5)
            r14.requestImmediateDataFlush()
        L51:
            boolean r14 = kotlinx.coroutines.E.x(r1)
            if (r14 == 0) goto L86
            r13.c = r1
            r13.a = r3
            r13.b = r2
            java.lang.Object r14 = kotlinx.coroutines.E.n(r3, r13)
            if (r14 != r0) goto L64
        L63:
            return r0
        L64:
            com.braze.support.BrazeLogger r5 = com.braze.support.BrazeLogger.INSTANCE
            java.lang.String r6 = com.braze.dispatch.f.m
            com.braze.support.BrazeLogger$Priority r7 = com.braze.support.BrazeLogger.Priority.V
            com.braze.configuration.h r10 = new com.braze.configuration.h
            r14 = 5
            r10.<init>(r14)
            r11 = 12
            r12 = 0
            r8 = 0
            r9 = 0
            com.braze.support.BrazeLogger.brazelog$default(r5, r6, r7, r8, r9, r10, r11, r12)
            com.braze.Braze$Companion r14 = com.braze.Braze.Companion
            com.braze.dispatch.f r5 = r13.d
            android.content.Context r5 = r5.a
            com.braze.Braze r14 = r14.getInstance(r5)
            r14.requestImmediateDataFlush()
            goto L51
        L86:
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.dispatch.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
