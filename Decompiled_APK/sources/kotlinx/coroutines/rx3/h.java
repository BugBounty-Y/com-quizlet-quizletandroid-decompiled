package kotlinx.coroutines.rx3;

import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC4992i l;
    public final /* synthetic */ C4899s m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(InterfaceC4992i interfaceC4992i, C4899s c4899s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC4992i;
        this.m = c4899s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.l, this.m, hVar);
        hVar2.k = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0053  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            io.reactivex.rxjava3.internal.operators.observable.s r2 = r7.m
            r3 = 1
            if (r1 == 0) goto L1d
            if (r1 != r3) goto L15
            java.lang.Object r0 = r7.k
            kotlinx.coroutines.C r0 = (kotlinx.coroutines.C) r0
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L13
            goto L39
        L13:
            r8 = move-exception
            goto L41
        L15:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.k
            kotlinx.coroutines.C r8 = (kotlinx.coroutines.C) r8
            kotlinx.coroutines.flow.i r1 = r7.l     // Catch: java.lang.Throwable -> L3d
            androidx.compose.foundation.text.input.internal.b r4 = new androidx.compose.foundation.text.input.internal.b     // Catch: java.lang.Throwable -> L3d
            r5 = 24
            r4.<init>(r2, r5)     // Catch: java.lang.Throwable -> L3d
            r7.k = r8     // Catch: java.lang.Throwable -> L3d
            r7.j = r3     // Catch: java.lang.Throwable -> L3d
            java.lang.Object r1 = r1.b(r4, r7)     // Catch: java.lang.Throwable -> L3d
            if (r1 != r0) goto L38
            return r0
        L38:
            r0 = r8
        L39:
            r2.onComplete()     // Catch: java.lang.Throwable -> L13
            goto L56
        L3d:
            r0 = move-exception
            r6 = r0
            r0 = r8
            r8 = r6
        L41:
            boolean r1 = r8 instanceof java.util.concurrent.CancellationException
            if (r1 != 0) goto L53
            boolean r1 = r2.e(r8)
            if (r1 != 0) goto L56
            kotlin.coroutines.CoroutineContext r0 = r0.getCoroutineContext()
            com.google.android.gms.internal.mlkit_vision_camera.J1.a(r0, r8)
            goto L56
        L53:
            r2.onComplete()
        L56:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.rx3.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
