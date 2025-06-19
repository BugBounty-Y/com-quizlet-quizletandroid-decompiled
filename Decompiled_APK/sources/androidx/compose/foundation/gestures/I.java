package androidx.compose.foundation.gestures;

import androidx.compose.animation.C0278e;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Q l;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B m;
    public final /* synthetic */ androidx.compose.animation.D n;
    public final /* synthetic */ C0278e o;
    public final /* synthetic */ J p;
    public final /* synthetic */ J q;
    public final /* synthetic */ androidx.compose.foundation.contextmenu.i r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(Q q, androidx.compose.ui.input.pointer.B b, androidx.compose.animation.D d, C0278e c0278e, J j, J j2, androidx.compose.foundation.contextmenu.i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = q;
        this.m = b;
        this.n = d;
        this.o = c0278e;
        this.p = j;
        this.q = j2;
        this.r = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        J j = this.q;
        androidx.compose.foundation.contextmenu.i iVar = this.r;
        I i = new I(this.l, this.m, this.n, this.o, this.p, j, iVar, hVar);
        i.k = obj;
        return i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [int, kotlinx.coroutines.C] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        ?? r1 = this.j;
        Q q = this.l;
        try {
            if (r1 == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
                EnumC0320d0 enumC0320d0 = q.p;
                androidx.compose.ui.input.pointer.B b = this.m;
                androidx.compose.animation.D d = this.n;
                C0278e c0278e = this.o;
                J j = this.p;
                J j2 = this.q;
                androidx.compose.foundation.contextmenu.i iVar = this.r;
                this.k = c;
                this.j = 1;
                float f = H.a;
                Object objD = AbstractC0349s0.d(b, new F(j2, new kotlin.jvm.internal.I(), enumC0320d0, d, iVar, j, c0278e, null), this);
                if (objD != obj2) {
                    objD = Unit.a;
                }
                if (objD == obj2) {
                    return obj2;
                }
            } else {
                if (r1 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
        } catch (CancellationException e) {
            kotlinx.coroutines.channels.h hVar = q.t;
            if (hVar != null) {
                hVar.o(C0352u.a);
            }
            if (!kotlinx.coroutines.E.x(r1)) {
                throw e;
            }
        }
        return Unit.a;
    }
}
