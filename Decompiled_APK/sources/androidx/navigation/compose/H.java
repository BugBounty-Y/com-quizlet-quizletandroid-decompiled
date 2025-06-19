package androidx.navigation.compose;

import androidx.compose.animation.C0297y;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.C1291m;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1276i l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ F0 n;
    public final /* synthetic */ InterfaceC0773a0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(C1276i c1276i, InterfaceC0773a0 interfaceC0773a0, F0 f0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1276i;
        this.m = interfaceC0773a0;
        this.n = f0;
        this.o = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        H h = new H(this.l, this.m, this.n, this.o, hVar);
        h.k = obj;
        return h;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((InterfaceC4992i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        C1291m c1291m;
        C1291m c1291m2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C1276i c1276i = this.l;
        InterfaceC0773a0 interfaceC0773a0 = this.m;
        InterfaceC0773a0 interfaceC0773a02 = this.o;
        try {
            if (i == 0) {
                Z.e(obj);
                InterfaceC4992i interfaceC4992i = (InterfaceC4992i) this.k;
                int size = ((List) interfaceC0773a0.getValue()).size();
                F0 f0 = this.n;
                if (size > 1) {
                    f0.j(DefinitionKt.NO_Float_VALUE);
                    c1291m = (C1291m) CollectionsKt.V((List) interfaceC0773a0.getValue());
                    Intrinsics.d(c1291m);
                    c1276i.h(c1291m);
                    c1276i.h((C1291m) ((List) interfaceC0773a0.getValue()).get(((List) interfaceC0773a0.getValue()).size() - 2));
                } else {
                    c1291m = null;
                }
                C0297y c0297y = new C0297y(interfaceC0773a0, interfaceC0773a02, f0);
                this.k = c1291m;
                this.j = 1;
                if (interfaceC4992i.b(c0297y, this) == aVar) {
                    return aVar;
                }
                c1291m2 = c1291m;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                c1291m2 = (C1291m) this.k;
                Z.e(obj);
            }
            if (((List) interfaceC0773a0.getValue()).size() > 1) {
                interfaceC0773a02.setValue(Boolean.FALSE);
                Intrinsics.d(c1291m2);
                c1276i.f(c1291m2, false);
            }
        } catch (CancellationException unused) {
            if (((List) interfaceC0773a0.getValue()).size() > 1) {
                interfaceC0773a02.setValue(Boolean.FALSE);
            }
        }
        return Unit.a;
    }
}
