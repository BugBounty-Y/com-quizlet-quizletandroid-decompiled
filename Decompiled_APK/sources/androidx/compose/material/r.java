package androidx.compose.material;

import androidx.compose.foundation.gestures.C0337m;
import androidx.compose.foundation.u0;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class r implements androidx.compose.foundation.gestures.Z {
    public final /* synthetic */ int a = 0;
    public final C0337m b;
    public final /* synthetic */ Object c;

    public r(androidx.work.impl.model.t tVar) {
        this.c = tVar;
        this.b = new C0337m(tVar, 2);
    }

    @Override // androidx.compose.foundation.gestures.Z
    public final Object a(androidx.compose.foundation.gestures.V v, androidx.compose.foundation.gestures.P p) throws Throwable {
        switch (this.a) {
            case 0:
                Object objA = ((C0575s) this.c).a(u0.b, new C0574q(this, v, null, 0), p);
                if (objA != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objC = ((androidx.work.impl.model.t) this.c).c(u0.b, new C0574q(this, v, null, 1), p);
                if (objC != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }

    public r(C0575s c0575s) {
        this.c = c0575s;
        this.b = new C0337m(c0575s, 1);
    }
}
