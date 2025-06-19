package androidx.compose.foundation.text;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ long m;
    public final /* synthetic */ androidx.compose.foundation.interaction.l n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B0(InterfaceC0773a0 interfaceC0773a0, long j, androidx.compose.foundation.interaction.l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC0773a0;
        this.m = j;
        this.n = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new B0(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0042, code lost:
    
        if (r2.c(r1, r8) == r0) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0053  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            androidx.compose.foundation.interaction.l r2 = r8.n
            r3 = 2
            r4 = 1
            androidx.compose.runtime.a0 r5 = r8.l
            if (r1 == 0) goto L28
            if (r1 == r4) goto L20
            if (r1 != r3) goto L18
            java.lang.Object r0 = r8.j
            androidx.compose.foundation.interaction.o r0 = (androidx.compose.foundation.interaction.o) r0
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5f
        L18:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L20:
            java.lang.Object r1 = r8.j
            androidx.compose.runtime.a0 r1 = (androidx.compose.runtime.InterfaceC0773a0) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L46
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r5.getValue()
            androidx.compose.foundation.interaction.o r9 = (androidx.compose.foundation.interaction.o) r9
            if (r9 == 0) goto L4a
            androidx.compose.foundation.interaction.n r1 = new androidx.compose.foundation.interaction.n
            r1.<init>(r9)
            if (r2 == 0) goto L45
            r8.j = r5
            r8.k = r4
            java.lang.Object r9 = r2.c(r1, r8)
            if (r9 != r0) goto L45
            goto L5d
        L45:
            r1 = r5
        L46:
            r9 = 0
            r1.setValue(r9)
        L4a:
            androidx.compose.foundation.interaction.o r9 = new androidx.compose.foundation.interaction.o
            long r6 = r8.m
            r9.<init>(r6)
            if (r2 == 0) goto L60
            r8.j = r9
            r8.k = r3
            java.lang.Object r1 = r2.c(r9, r8)
            if (r1 != r0) goto L5e
        L5d:
            return r0
        L5e:
            r0 = r9
        L5f:
            r9 = r0
        L60:
            r5.setValue(r9)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.B0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
