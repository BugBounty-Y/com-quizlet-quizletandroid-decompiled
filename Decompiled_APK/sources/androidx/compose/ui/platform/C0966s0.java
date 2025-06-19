package androidx.compose.ui.platform;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.ui.platform.s0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0966s0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.w j;
    public kotlinx.coroutines.channels.c k;
    public int l;
    public final /* synthetic */ kotlinx.coroutines.channels.h m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0966s0(kotlinx.coroutines.channels.h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0966s0(this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0966s0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0032 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x003b A[Catch: all -> 0x0011, TryCatch #0 {all -> 0x0011, blocks: (B:6:0x000d, B:17:0x0033, B:19:0x003b, B:20:0x0049, B:28:0x005a, B:14:0x0026, B:30:0x005d, B:31:0x0061, B:32:0x0062, B:33:0x0063, B:13:0x0020, B:21:0x004a, B:23:0x0050), top: B:40:0x0005, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0063 A[Catch: all -> 0x0011, TRY_LEAVE, TryCatch #0 {all -> 0x0011, blocks: (B:6:0x000d, B:17:0x0033, B:19:0x003b, B:20:0x0049, B:28:0x005a, B:14:0x0026, B:30:0x005d, B:31:0x0061, B:32:0x0062, B:33:0x0063, B:13:0x0020, B:21:0x004a, B:23:0x0050), top: B:40:0x0005, inners: #1 }] */
    /* JADX WARN: Type inference failed for: r3v4, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x0030 -> B:17:0x0033). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r2 = 1
            if (r1 == 0) goto L1b
            if (r1 != r2) goto L13
            kotlinx.coroutines.channels.c r1 = r6.k
            kotlinx.coroutines.channels.w r3 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L11
            goto L33
        L11:
            r7 = move-exception
            goto L6c
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.channels.h r3 = r6.m
            kotlinx.coroutines.channels.c r7 = new kotlinx.coroutines.channels.c     // Catch: java.lang.Throwable -> L11
            r7.<init>(r3)     // Catch: java.lang.Throwable -> L11
            r1 = r7
        L26:
            r6.j = r3     // Catch: java.lang.Throwable -> L11
            r6.k = r1     // Catch: java.lang.Throwable -> L11
            r6.l = r2     // Catch: java.lang.Throwable -> L11
            java.lang.Object r7 = r1.b(r6)     // Catch: java.lang.Throwable -> L11
            if (r7 != r0) goto L33
            return r0
        L33:
            java.lang.Boolean r7 = (java.lang.Boolean) r7     // Catch: java.lang.Throwable -> L11
            boolean r7 = r7.booleanValue()     // Catch: java.lang.Throwable -> L11
            if (r7 == 0) goto L63
            java.lang.Object r7 = r1.c()     // Catch: java.lang.Throwable -> L11
            kotlin.Unit r7 = (kotlin.Unit) r7     // Catch: java.lang.Throwable -> L11
            java.util.concurrent.atomic.AtomicBoolean r7 = androidx.compose.ui.platform.AbstractC0968t0.b     // Catch: java.lang.Throwable -> L11
            r4 = 0
            r7.set(r4)     // Catch: java.lang.Throwable -> L11
            java.lang.Object r7 = androidx.compose.runtime.snapshots.m.b     // Catch: java.lang.Throwable -> L11
            monitor-enter(r7)     // Catch: java.lang.Throwable -> L11
            androidx.compose.runtime.snapshots.c r5 = androidx.compose.runtime.snapshots.m.i     // Catch: java.lang.Throwable -> L58
            androidx.collection.J r5 = r5.h     // Catch: java.lang.Throwable -> L58
            if (r5 == 0) goto L5a
            boolean r5 = r5.h()     // Catch: java.lang.Throwable -> L58
            if (r5 != r2) goto L5a
            r4 = r2
            goto L5a
        L58:
            r0 = move-exception
            goto L61
        L5a:
            monitor-exit(r7)     // Catch: java.lang.Throwable -> L11
            if (r4 == 0) goto L26
            androidx.compose.runtime.snapshots.m.a()     // Catch: java.lang.Throwable -> L11
            goto L26
        L61:
            monitor-exit(r7)     // Catch: java.lang.Throwable -> L11
            throw r0     // Catch: java.lang.Throwable -> L11
        L63:
            kotlin.Unit r7 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L11
            r7 = 0
            r3.j(r7)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L6c:
            throw r7     // Catch: java.lang.Throwable -> L6d
        L6d:
            r0 = move-exception
            com.google.android.gms.internal.mlkit_vision_camera.E1.a(r3, r7)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0966s0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
