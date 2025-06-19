package com.quizlet.features.folders.viewmodel;

import com.quizlet.features.folders.data.EnumC4270a;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.folders.data.U;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public s0 j;
    public EnumC4270a k;
    public N l;
    public Object m;
    public U n;
    public Q0 o;
    public int p;
    public final /* synthetic */ N q;
    public final /* synthetic */ EnumC4270a r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(N n, EnumC4270a enumC4270a, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = n;
        this.r = enumC4270a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.q, this.r, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:11:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0082  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:10:0x003a -> B:20:0x007c). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:14:0x005e -> B:16:0x0061). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0066 -> B:17:0x0064). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            r18 = this;
            r0 = r18
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L25
            if (r2 != r3) goto L1d
            com.quizlet.features.folders.data.Q0 r2 = r0.o
            com.quizlet.features.folders.data.U r4 = r0.n
            java.lang.Object r5 = r0.m
            com.quizlet.features.folders.viewmodel.N r6 = r0.l
            com.quizlet.features.folders.data.a r7 = r0.k
            kotlinx.coroutines.flow.s0 r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r19)
            r9 = r19
            goto L61
        L1d:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r19)
            com.quizlet.features.folders.viewmodel.N r2 = r0.q
            kotlinx.coroutines.flow.s0 r4 = r2.u
            com.quizlet.features.folders.data.a r5 = r0.r
            r6 = r2
            r8 = r4
            r7 = r5
        L31:
            java.lang.Object r5 = r8.getValue()
            r4 = r5
            com.quizlet.features.folders.data.W r4 = (com.quizlet.features.folders.data.W) r4
            boolean r2 = r4 instanceof com.quizlet.features.folders.data.U
            if (r2 == 0) goto L7c
            r2 = r4
            com.quizlet.features.folders.data.U r2 = (com.quizlet.features.folders.data.U) r2
            com.quizlet.features.folders.data.Q0 r2 = r2.a
            if (r7 != 0) goto L66
            com.quizlet.data.repository.activitycenter.b r9 = r6.l
            boolean r10 = r2.m
            r0.j = r8
            r0.k = r7
            r0.l = r6
            r0.m = r5
            r11 = r4
            com.quizlet.features.folders.data.U r11 = (com.quizlet.features.folders.data.U) r11
            r0.n = r11
            r0.o = r2
            r0.p = r3
            long r11 = r6.r
            java.lang.Enum r9 = r9.i(r11, r10, r0)
            if (r9 != r1) goto L61
            return r1
        L61:
            com.quizlet.features.folders.data.a r9 = (com.quizlet.features.folders.data.EnumC4270a) r9
            r14 = r9
        L64:
            r10 = r2
            goto L68
        L66:
            r14 = r7
            goto L64
        L68:
            com.quizlet.features.folders.data.U r4 = (com.quizlet.features.folders.data.U) r4
            r13 = 0
            r15 = 0
            r11 = 0
            r12 = 0
            r17 = 1032191(0xfbfff, float:1.446408E-39)
            com.quizlet.features.folders.data.Q0 r2 = com.quizlet.features.folders.data.Q0.a(r10, r11, r12, r13, r14, r15, r17)
            r9 = 2
            r10 = 0
            com.quizlet.features.folders.data.U r4 = com.quizlet.features.folders.data.U.a(r4, r2, r10, r9)
        L7c:
            boolean r2 = r8.k(r5, r4)
            if (r2 == 0) goto L31
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.L.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
