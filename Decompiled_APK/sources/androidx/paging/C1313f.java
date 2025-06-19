package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.paging.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1313f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ InterfaceC4992i k;
    public final /* synthetic */ com.quizlet.remote.model.notes.e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1313f(InterfaceC4992i interfaceC4992i, com.quizlet.remote.model.notes.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = interfaceC4992i;
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1313f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1313f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0496b c0496b = new C0496b(this.l, 3);
            this.j = 1;
            Object objB = this.k.b(new C1307c(c0496b, new kotlin.jvm.internal.H()), this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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
