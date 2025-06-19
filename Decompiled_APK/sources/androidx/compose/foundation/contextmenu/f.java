package androidx.compose.foundation.contextmenu;

import androidx.compose.ui.input.pointer.z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ androidx.camera.lifecycle.f m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(androidx.camera.lifecycle.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.m, hVar);
        fVar.l = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0059, code lost:
    
        if (r8 == r0) goto L15;
     */
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
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L20
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5c
        L10:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L18:
            java.lang.Object r1 = r7.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L33
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.l
            r1 = r8
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            r7.l = r1
            r7.k = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.Y.a(r1, r7)
            if (r8 != r0) goto L33
            goto L5b
        L33:
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            r8.a()
            androidx.camera.lifecycle.f r3 = r7.m
            androidx.compose.foundation.contextmenu.m r4 = new androidx.compose.foundation.contextmenu.m
            long r5 = r8.c
            r4.<init>(r5)
            java.lang.Object r8 = r3.b
            androidx.compose.foundation.contextmenu.o r8 = (androidx.compose.foundation.contextmenu.o) r8
            androidx.compose.runtime.a0 r8 = r8.a
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8
            r8.setValue(r4)
            kotlin.Unit r8 = kotlin.Unit.a
            r8 = 0
            r7.l = r8
            r7.k = r2
            androidx.compose.ui.input.pointer.g r8 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r8 = androidx.compose.foundation.gestures.k1.e(r1, r8, r7)
            if (r8 != r0) goto L5c
        L5b:
            return r0
        L5c:
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            if (r8 == 0) goto L63
            r8.a()
        L63:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.contextmenu.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
