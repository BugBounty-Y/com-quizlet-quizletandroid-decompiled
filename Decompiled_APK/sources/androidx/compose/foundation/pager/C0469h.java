package androidx.compose.foundation.pager;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.pager.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0469h extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public androidx.compose.ui.input.pointer.n k;
    public androidx.compose.ui.input.pointer.n l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C0466e o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0469h(C0466e c0466e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = c0466e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0469h c0469h = new C0469h(this.o, hVar);
        c0469h.n = obj;
        return c0469h;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0469h) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x003d, code lost:
    
        if (r13 == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0062, code lost:
    
        if (r13 == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0064, code lost:
    
        return r0;
     */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x008a  */
    /* JADX WARN: Type inference failed for: r13v11, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0062 -> B:18:0x0065). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.m
            androidx.compose.ui.input.pointer.g r2 = androidx.compose.ui.input.pointer.g.a
            r3 = 1
            androidx.compose.foundation.pager.e r4 = r12.o
            r5 = 2
            r6 = 0
            if (r1 == 0) goto L2d
            if (r1 == r3) goto L25
            if (r1 != r5) goto L1d
            androidx.compose.ui.input.pointer.n r1 = r12.l
            androidx.compose.ui.input.pointer.n r3 = r12.k
            java.lang.Object r7 = r12.n
            androidx.compose.ui.input.pointer.z r7 = (androidx.compose.ui.input.pointer.z) r7
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L65
        L1d:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L25:
            java.lang.Object r1 = r12.n
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L40
        L2d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.n
            r1 = r13
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            r12.n = r1
            r12.m = r3
            java.lang.Object r13 = androidx.compose.foundation.gestures.k1.b(r1, r6, r2, r12)
            if (r13 != r0) goto L40
            goto L64
        L40:
            androidx.compose.ui.input.pointer.n r13 = (androidx.compose.ui.input.pointer.n) r13
            androidx.compose.runtime.a0 r3 = r4.a
            androidx.compose.ui.geometry.b r7 = new androidx.compose.ui.geometry.b
            r8 = 0
            r7.<init>(r8)
            androidx.compose.runtime.L0 r3 = (androidx.compose.runtime.L0) r3
            r3.setValue(r7)
            r3 = 0
            r7 = r1
            r1 = r3
            r3 = r13
        L54:
            if (r1 != 0) goto L8a
            r12.n = r7
            r12.k = r3
            r12.l = r1
            r12.m = r5
            java.lang.Object r13 = r7.c(r2, r12)
            if (r13 != r0) goto L65
        L64:
            return r0
        L65:
            androidx.compose.ui.input.pointer.f r13 = (androidx.compose.ui.input.pointer.f) r13
            java.lang.Object r8 = r13.a
            int r9 = r8.size()
            r10 = r6
        L6e:
            if (r10 >= r9) goto L80
            java.lang.Object r11 = r8.get(r10)
            androidx.compose.ui.input.pointer.n r11 = (androidx.compose.ui.input.pointer.n) r11
            boolean r11 = androidx.compose.ui.input.pointer.l.b(r11)
            if (r11 != 0) goto L7d
            goto L54
        L7d:
            int r10 = r10 + 1
            goto L6e
        L80:
            java.lang.Object r13 = r13.a
            java.lang.Object r13 = r13.get(r6)
            r1 = r13
            androidx.compose.ui.input.pointer.n r1 = (androidx.compose.ui.input.pointer.n) r1
            goto L54
        L8a:
            long r2 = r3.c
            long r0 = r1.c
            long r0 = androidx.compose.ui.geometry.b.g(r0, r2)
            androidx.compose.runtime.a0 r13 = r4.a
            androidx.compose.ui.geometry.b r2 = new androidx.compose.ui.geometry.b
            r2.<init>(r0)
            androidx.compose.runtime.L0 r13 = (androidx.compose.runtime.L0) r13
            r13.setValue(r2)
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.C0469h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
