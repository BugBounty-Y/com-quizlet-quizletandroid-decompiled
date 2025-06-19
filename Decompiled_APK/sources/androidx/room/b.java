package androidx.room;

import androidx.work.impl.WorkDatabase_Impl;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.c j;
    public int k;
    public final /* synthetic */ WorkDatabase_Impl l;
    public final /* synthetic */ c m;
    public final /* synthetic */ kotlinx.coroutines.channels.h n;
    public final /* synthetic */ androidx.work.impl.model.s o;
    public final /* synthetic */ kotlinx.coroutines.channels.h p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(WorkDatabase_Impl workDatabase_Impl, c cVar, kotlinx.coroutines.channels.h hVar, androidx.work.impl.model.s sVar, kotlinx.coroutines.channels.h hVar2, kotlin.coroutines.h hVar3) {
        super(2, hVar3);
        this.l = workDatabase_Impl;
        this.m = cVar;
        this.n = hVar;
        this.o = sVar;
        this.p = hVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0048 A[Catch: all -> 0x0018, TRY_LEAVE, TryCatch #0 {all -> 0x0018, blocks: (B:7:0x0014, B:18:0x0035, B:21:0x0040, B:23:0x0048, B:14:0x0024, B:17:0x002e), top: B:30:0x000c }] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x005e  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:24:0x005b -> B:18:0x0035). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.k
            androidx.room.c r2 = r7.m
            androidx.work.impl.WorkDatabase_Impl r3 = r7.l
            r4 = 2
            r5 = 1
            androidx.room.n r3 = r3.e
            if (r1 == 0) goto L28
            if (r1 == r5) goto L22
            if (r1 != r4) goto L1a
            kotlinx.coroutines.channels.c r1 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L18
            goto L35
        L18:
            r8 = move-exception
            goto L64
        L1a:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L22:
            kotlinx.coroutines.channels.c r1 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L18
            goto L40
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r3.a(r2)
            kotlinx.coroutines.channels.h r8 = r7.n     // Catch: java.lang.Throwable -> L18
            kotlinx.coroutines.channels.c r1 = new kotlinx.coroutines.channels.c     // Catch: java.lang.Throwable -> L18
            r1.<init>(r8)     // Catch: java.lang.Throwable -> L18
        L35:
            r7.j = r1     // Catch: java.lang.Throwable -> L18
            r7.k = r5     // Catch: java.lang.Throwable -> L18
            java.lang.Object r8 = r1.b(r7)     // Catch: java.lang.Throwable -> L18
            if (r8 != r0) goto L40
            goto L5d
        L40:
            java.lang.Boolean r8 = (java.lang.Boolean) r8     // Catch: java.lang.Throwable -> L18
            boolean r8 = r8.booleanValue()     // Catch: java.lang.Throwable -> L18
            if (r8 == 0) goto L5e
            r1.c()     // Catch: java.lang.Throwable -> L18
            androidx.work.impl.model.s r8 = r7.o     // Catch: java.lang.Throwable -> L18
            java.lang.Object r8 = r8.call()     // Catch: java.lang.Throwable -> L18
            kotlinx.coroutines.channels.h r6 = r7.p     // Catch: java.lang.Throwable -> L18
            r7.j = r1     // Catch: java.lang.Throwable -> L18
            r7.k = r4     // Catch: java.lang.Throwable -> L18
            java.lang.Object r8 = r6.s(r8, r7)     // Catch: java.lang.Throwable -> L18
            if (r8 != r0) goto L35
        L5d:
            return r0
        L5e:
            r3.c(r2)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L64:
            r3.c(r2)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.room.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
