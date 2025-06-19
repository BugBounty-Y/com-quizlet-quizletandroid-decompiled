package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class Y0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.c j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ InterfaceC5002j m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public Y0(InterfaceC5002j interfaceC5002j, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = interfaceC5002j;
        this.n = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Y0 y0 = new Y0(this.m, this.n, hVar);
        y0.l = obj;
        return y0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Y0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0072, code lost:
    
        if (r8.m.emit(r9, r8) == r0) goto L20;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0075  */
    /* JADX WARN: Type inference failed for: r5v11, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r5v9, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r6v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:19:0x0072 -> B:7:0x0016). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            r2 = 0
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L2b
            if (r1 == r4) goto L21
            if (r1 != r3) goto L19
            kotlinx.coroutines.channels.c r1 = r8.j
            java.lang.Object r5 = r8.l
            kotlinx.coroutines.j0 r5 = (kotlinx.coroutines.InterfaceC5025j0) r5
            androidx.glance.appwidget.protobuf.Z.e(r9)
        L16:
            r9 = r5
            r5 = r1
            goto L49
        L19:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L21:
            kotlinx.coroutines.channels.c r1 = r8.j
            java.lang.Object r5 = r8.l
            kotlinx.coroutines.j0 r5 = (kotlinx.coroutines.InterfaceC5025j0) r5
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5a
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.l
            kotlinx.coroutines.C r9 = (kotlinx.coroutines.C) r9
            r1 = 0
            r5 = 6
            kotlinx.coroutines.channels.h r1 = com.google.android.gms.internal.mlkit_vision_camera.D1.a(r1, r5, r2)
            androidx.paging.X0 r5 = new androidx.paging.X0
            kotlin.coroutines.jvm.internal.i r6 = r8.n
            r5.<init>(r1, r6, r2)
            r6 = 3
            kotlinx.coroutines.y0 r9 = kotlinx.coroutines.E.A(r9, r2, r2, r5, r6)
            kotlinx.coroutines.channels.c r5 = new kotlinx.coroutines.channels.c
            r5.<init>(r1)
        L49:
            r8.l = r9
            r8.j = r5
            r8.k = r4
            java.lang.Object r1 = r5.b(r8)
            if (r1 != r0) goto L56
            goto L74
        L56:
            r7 = r5
            r5 = r9
            r9 = r1
            r1 = r7
        L5a:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L75
            java.lang.Object r9 = r1.c()
            r8.l = r5
            r8.j = r1
            r8.k = r3
            kotlinx.coroutines.flow.j r6 = r8.m
            java.lang.Object r9 = r6.emit(r9, r8)
            if (r9 != r0) goto L16
        L74:
            return r0
        L75:
            r5.j(r2)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.Y0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
