package androidx.compose.foundation.contextmenu;

import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.text.selection.C0536q;
import androidx.compose.foundation.text.selection.W;
import androidx.compose.material3.AbstractC0625h;
import androidx.compose.material3.B2;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.V;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b extends r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public b(h hVar, Function0 function0, c cVar, Function1 function1, int i) {
        super(2);
        this.a = 1;
        this.e = hVar;
        this.b = function0;
        this.f = cVar;
        this.c = (r) function1;
        this.d = i;
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.d | 1);
                ?? r3 = (r) this.c;
                V.a((o) this.e, (Function0) this.b, (androidx.compose.ui.q) this.f, r3, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.d | 1);
                ?? r32 = (r) this.c;
                q.c((h) this.e, (Function0) this.b, (c) this.f, r32, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.c;
                W.b((androidx.compose.ui.n) this.e, (C0536q) this.b, (Function1) this.f, dVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Number) obj2).intValue();
                int iH4 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.c;
                AbstractC0625h.d((Function0) this.b, (androidx.compose.ui.q) this.f, (androidx.compose.ui.window.r) this.e, dVar2, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Number) obj2).intValue();
                int iH5 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar3 = (androidx.compose.runtime.internal.d) this.c;
                Z1.i((Function0) this.b, (B2) this.e, (C0238e) this.f, dVar3, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Number) obj2).intValue();
                int iH6 = C0776c.H(this.d) | 1;
                Object obj3 = this.f;
                Object obj4 = this.c;
                ((androidx.compose.runtime.internal.d) this.e).e(this.b, obj3, obj4, (InterfaceC0806l) obj, iH6);
                break;
            default:
                ((Number) obj2).intValue();
                androidx.compose.ui.viewinterop.k.c((kotlin.jvm.functions.c) this.e, (androidx.compose.ui.q) this.f, (androidx.compose.ui.viewinterop.a) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(this.d | 1));
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public b(o oVar, Function0 function0, androidx.compose.ui.q qVar, Function1 function1, int i) {
        super(2);
        this.a = 0;
        this.e = oVar;
        this.b = function0;
        this.f = qVar;
        this.c = (r) function1;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(Object obj, Object obj2, Object obj3, Object obj4, int i, int i2) {
        super(2);
        this.a = i2;
        this.e = obj;
        this.b = obj2;
        this.f = obj3;
        this.c = obj4;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Function0 function0, B2 b2, C0238e c0238e, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = 4;
        this.b = function0;
        this.e = b2;
        this.f = c0238e;
        this.c = dVar;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Function0 function0, androidx.compose.ui.q qVar, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = 3;
        this.b = function0;
        this.f = qVar;
        this.e = rVar;
        this.c = dVar;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(kotlin.jvm.functions.c cVar, androidx.compose.ui.q qVar, androidx.compose.ui.viewinterop.a aVar, Function1 function1, int i) {
        super(2);
        this.a = 6;
        this.e = cVar;
        this.f = qVar;
        this.b = aVar;
        this.c = function1;
        this.d = i;
    }
}
