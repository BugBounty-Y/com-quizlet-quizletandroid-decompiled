package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0548w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0492h0 k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ androidx.compose.ui.text.input.B m;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 n;
    public final /* synthetic */ androidx.compose.ui.text.input.m o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0548w(C0492h0 c0492h0, InterfaceC0773a0 interfaceC0773a0, androidx.compose.ui.text.input.B b, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.text.input.m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0492h0;
        this.l = interfaceC0773a0;
        this.m = b;
        this.n = i0Var;
        this.o = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0548w(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0548w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0492h0 c0492h0 = this.k;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                C1087t c1087tF = C0776c.F(new androidx.compose.foundation.lazy.j(this.l, 4));
                androidx.compose.foundation.K k = new androidx.compose.foundation.K(c0492h0, this.m, this.n, this.o, 1);
                this.j = 1;
                if (c1087tF.b(k, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            AbstractC0484d0.k(c0492h0);
            return Unit.a;
        } catch (Throwable th) {
            AbstractC0484d0.k(c0492h0);
            throw th;
        }
    }
}
