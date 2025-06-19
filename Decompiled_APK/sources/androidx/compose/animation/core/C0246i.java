package androidx.compose.animation.core;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.core.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0246i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.c j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlinx.coroutines.channels.l m;
    public final /* synthetic */ C0238e n;
    public final /* synthetic */ InterfaceC0773a0 o;
    public final /* synthetic */ InterfaceC0773a0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0246i(kotlinx.coroutines.channels.l lVar, C0238e c0238e, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = lVar;
        this.n = c0238e;
        this.o = interfaceC0773a0;
        this.p = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0246i c0246i = new C0246i(this.m, this.n, this.o, this.p, hVar);
        c0246i.l = obj;
        return c0246i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0246i) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0035 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0061  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:10:0x0033 -> B:12:0x0036). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            kotlinx.coroutines.channels.l r2 = r12.m
            r3 = 1
            if (r1 == 0) goto L1d
            if (r1 != r3) goto L15
            kotlinx.coroutines.channels.c r1 = r12.j
            java.lang.Object r4 = r12.l
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L36
        L15:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.l
            kotlinx.coroutines.C r13 = (kotlinx.coroutines.C) r13
            kotlinx.coroutines.channels.c r1 = r2.iterator()
            r4 = r13
        L29:
            r12.l = r4
            r12.j = r1
            r12.k = r3
            java.lang.Object r13 = r1.b(r12)
            if (r13 != r0) goto L36
            return r0
        L36:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            if (r13 == 0) goto L61
            java.lang.Object r13 = r1.c()
            java.lang.Object r5 = r2.h()
            java.lang.Object r5 = kotlinx.coroutines.channels.o.b(r5)
            if (r5 != 0) goto L4e
            r7 = r13
            goto L4f
        L4e:
            r7 = r5
        L4f:
            androidx.compose.animation.core.h r6 = new androidx.compose.animation.core.h
            androidx.compose.runtime.a0 r10 = r12.p
            androidx.compose.runtime.a0 r9 = r12.o
            androidx.compose.animation.core.e r8 = r12.n
            r11 = 0
            r6.<init>(r7, r8, r9, r10, r11)
            r13 = 3
            r5 = 0
            kotlinx.coroutines.E.A(r4, r5, r5, r6, r13)
            goto L29
        L61:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.C0246i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
