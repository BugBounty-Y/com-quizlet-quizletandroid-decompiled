package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0372l extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0456n m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0372l(C0456n c0456n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c0456n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0372l c0372l = new C0372l(this.m, hVar);
        c0372l.l = obj;
        return c0372l;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0372l) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0036, code lost:
    
        if (r13 == r0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0057, code lost:
    
        if (r13 != r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0059, code lost:
    
        return r0;
     */
    /* JADX WARN: Type inference failed for: r13v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x0057 -> B:17:0x005a). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            r2 = 2
            r3 = 1
            androidx.compose.foundation.n r4 = r12.m
            if (r1 == 0) goto L26
            if (r1 == r3) goto L1e
            if (r1 != r2) goto L16
            java.lang.Object r1 = r12.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L5a
        L16:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1e:
            java.lang.Object r1 = r12.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L39
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.l
            r1 = r13
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            r12.l = r1
            r12.k = r3
            java.lang.Object r13 = androidx.compose.foundation.gestures.k1.c(r1, r12, r2)
            if (r13 != r0) goto L39
            goto L59
        L39:
            androidx.compose.ui.input.pointer.n r13 = (androidx.compose.ui.input.pointer.n) r13
            long r5 = r13.a
            androidx.compose.ui.input.pointer.m r3 = new androidx.compose.ui.input.pointer.m
            r3.<init>(r5)
            r4.g = r3
            androidx.compose.ui.geometry.b r3 = new androidx.compose.ui.geometry.b
            long r5 = r13.c
            r3.<init>(r5)
            r4.a = r3
        L4d:
            r12.l = r1
            r12.k = r2
            androidx.compose.ui.input.pointer.g r13 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r13 = r1.c(r13, r12)
            if (r13 != r0) goto L5a
        L59:
            return r0
        L5a:
            androidx.compose.ui.input.pointer.f r13 = (androidx.compose.ui.input.pointer.f) r13
            java.lang.Object r13 = r13.a
            java.util.ArrayList r3 = new java.util.ArrayList
            int r5 = r13.size()
            r3.<init>(r5)
            int r5 = r13.size()
            r6 = 0
            r7 = r6
        L6d:
            if (r7 >= r5) goto L80
            java.lang.Object r8 = r13.get(r7)
            r9 = r8
            androidx.compose.ui.input.pointer.n r9 = (androidx.compose.ui.input.pointer.n) r9
            boolean r9 = r9.d
            if (r9 == 0) goto L7d
            r3.add(r8)
        L7d:
            int r7 = r7 + 1
            goto L6d
        L80:
            int r13 = r3.size()
        L84:
            r5 = 0
            if (r6 >= r13) goto L9e
            java.lang.Object r7 = r3.get(r6)
            r8 = r7
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            long r8 = r8.a
            androidx.compose.ui.input.pointer.m r10 = r4.g
            if (r10 != 0) goto L95
            goto L9b
        L95:
            long r10 = r10.a
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L9f
        L9b:
            int r6 = r6 + 1
            goto L84
        L9e:
            r7 = r5
        L9f:
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
            if (r7 != 0) goto Laa
            java.lang.Object r13 = kotlin.collections.CollectionsKt.firstOrNull(r3)
            r7 = r13
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
        Laa:
            if (r7 == 0) goto Lbe
            androidx.compose.ui.input.pointer.m r13 = new androidx.compose.ui.input.pointer.m
            long r8 = r7.a
            r13.<init>(r8)
            r4.g = r13
            androidx.compose.ui.geometry.b r13 = new androidx.compose.ui.geometry.b
            long r6 = r7.c
            r13.<init>(r6)
            r4.a = r13
        Lbe:
            boolean r13 = r3.isEmpty()
            if (r13 == 0) goto L4d
            r4.g = r5
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0372l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
