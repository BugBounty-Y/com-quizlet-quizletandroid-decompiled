package androidx.compose.foundation.pager;

import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.InterfaceC0256n;
import androidx.compose.foundation.gestures.C0330i0;
import androidx.compose.foundation.gestures.InterfaceC0334k0;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0281h l;
    public final /* synthetic */ int m;
    public final /* synthetic */ com.google.android.gms.auth.api.signin.internal.h n;
    public final /* synthetic */ float o;
    public final /* synthetic */ InterfaceC0256n p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(C0281h c0281h, int i, com.google.android.gms.auth.api.signin.internal.h hVar, float f, InterfaceC0256n interfaceC0256n, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = c0281h;
        this.m = i;
        this.n = hVar;
        this.o = f;
        this.p = interfaceC0256n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        G g = new G(this.l, this.m, this.n, this.o, this.p, hVar);
        g.k = obj;
        return g;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i2 = this.j;
        if (i2 == 0) {
            Z.e(obj);
            InterfaceC0334k0 interfaceC0334k0 = (InterfaceC0334k0) this.k;
            int i3 = this.m;
            this.l.invoke(interfaceC0334k0, new Integer(i3));
            com.google.android.gms.auth.api.signin.internal.h hVar = this.n;
            boolean z = i3 > ((E) hVar.b).d;
            int iM = hVar.m();
            E e = (E) hVar.b;
            int i4 = (iM - e.d) + 1;
            if (((z && i3 > hVar.m()) || (!z && i3 < e.d)) && Math.abs(i3 - e.d) >= 3) {
                if (z) {
                    int i5 = i;
                    hVar.t(i5, 0);
                } else {
                    int i52 = i;
                    hVar.t(i52, 0);
                }
            }
            float fX = hVar.x(i3) + this.o;
            C0330i0 c0330i0 = new C0330i0(new kotlin.jvm.internal.G(), interfaceC0334k0, 1);
            this.j = 1;
            if (AbstractC0240f.e(DefinitionKt.NO_Float_VALUE, fX, this.p, c0330i0, this, 4) == aVar) {
                return aVar;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
