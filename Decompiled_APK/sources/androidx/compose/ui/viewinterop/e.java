package androidx.compose.ui.viewinterop;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ i l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(boolean z, i iVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = iVar;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0034, code lost:
    
        if (r11.a.a(0, r10.m, r10) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0044, code lost:
    
        if (r11.a.a(r10.m, 0, r10) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0046, code lost:
    
        return r0;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1d
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L47
        L10:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r6 = r10
            goto L47
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            androidx.compose.ui.viewinterop.i r11 = r10.l
            boolean r1 = r10.k
            if (r1 != 0) goto L37
            r10.j = r3
            r5 = 0
            long r7 = r10.m
            androidx.compose.ui.input.nestedscroll.e r4 = r11.a
            r9 = r10
            java.lang.Object r11 = r4.a(r5, r7, r9)
            r6 = r9
            if (r11 != r0) goto L47
            goto L46
        L37:
            r6 = r10
            r6.j = r2
            long r2 = r6.m
            r4 = 0
            androidx.compose.ui.input.nestedscroll.e r1 = r11.a
            java.lang.Object r11 = r1.a(r2, r4, r6)
            if (r11 != r0) goto L47
        L46:
            return r0
        L47:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.viewinterop.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
