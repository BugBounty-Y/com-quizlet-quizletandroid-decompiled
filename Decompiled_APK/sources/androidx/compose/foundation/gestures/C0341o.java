package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0230a;
import androidx.compose.animation.core.C0258o;
import androidx.compose.animation.core.C0276z;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0341o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.G j;
    public C0258o k;
    public int l;
    public final /* synthetic */ float m;
    public final /* synthetic */ C0343p n;
    public final /* synthetic */ G0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0341o(float f, C0343p c0343p, G0 g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = f;
        this.n = c0343p;
        this.o = g0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0341o(this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0341o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        float f;
        C0258o c0258o;
        kotlin.jvm.internal.G g;
        C0276z c0276z;
        C0230a c0230a;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            f = this.m;
            if (Math.abs(f) > 1.0f) {
                kotlin.jvm.internal.G g2 = new kotlin.jvm.internal.G();
                g2.a = f;
                kotlin.jvm.internal.G g3 = new kotlin.jvm.internal.G();
                C0258o c0258oB = AbstractC0240f.b(DefinitionKt.NO_Float_VALUE, f, 28);
                try {
                    C0343p c0343p = this.n;
                    c0276z = c0343p.a;
                    c0230a = new C0230a(g3, this.o, g2, c0343p, 2);
                    this.j = g2;
                    this.k = c0258oB;
                    this.l = 1;
                } catch (CancellationException unused) {
                    c0258o = c0258oB;
                    g = g2;
                    g.a = ((Number) c0258o.a()).floatValue();
                    f = g.a;
                    return new Float(f);
                }
                if (AbstractC0240f.f(c0258oB, c0276z, false, c0230a, this) == aVar) {
                    return aVar;
                }
                g = g2;
                f = g.a;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            c0258o = this.k;
            g = this.j;
            try {
                androidx.glance.appwidget.protobuf.Z.e(obj);
            } catch (CancellationException unused2) {
                g.a = ((Number) c0258o.a()).floatValue();
                f = g.a;
                return new Float(f);
            }
            f = g.a;
        }
        return new Float(f);
    }
}
