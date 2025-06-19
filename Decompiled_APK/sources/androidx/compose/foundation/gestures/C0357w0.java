package androidx.compose.foundation.gestures;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.w0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0357w0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ D0 k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0357w0(D0 d0, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = d0;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0357w0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0357w0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objInvokeSuspend;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            L0 l0 = this.k.C;
            this.j = 1;
            EnumC0320d0 enumC0320d0 = l0.d;
            EnumC0320d0 enumC0320d02 = EnumC0320d0.b;
            long j = this.l;
            long jA = enumC0320d0 == enumC0320d02 ? androidx.compose.ui.unit.o.a(j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1) : androidx.compose.ui.unit.o.a(j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 2);
            J0 j0 = new J0(l0, null);
            androidx.compose.foundation.C0 c0 = l0.b;
            if (c0 == null || !(l0.a.d() || l0.a.b())) {
                J0 j02 = new J0(j0.m, this);
                j02.l = jA;
                objInvokeSuspend = j02.invokeSuspend(Unit.a);
                if (objInvokeSuspend != aVar) {
                    objInvokeSuspend = Unit.a;
                }
            } else {
                objInvokeSuspend = c0.b(jA, j0, this);
                if (objInvokeSuspend != aVar) {
                    objInvokeSuspend = Unit.a;
                }
            }
            if (objInvokeSuspend == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
