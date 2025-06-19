package androidx.compose.foundation.layout;

import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.material3.O3;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.layout.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0419y extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0419y(androidx.compose.foundation.lazy.layout.N n, Object obj, int i, Object obj2, int i2) {
        super(2);
        this.a = 1;
        this.d = n;
        this.e = obj;
        this.b = i;
        this.f = obj2;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.b | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                androidx.compose.ui.i iVar = (androidx.compose.ui.i) this.e;
                AbstractC0382e.a((androidx.compose.ui.q) this.d, iVar, dVar, (InterfaceC0806l) obj, iH, this.c);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.c | 1);
                int i = this.b;
                Object obj3 = this.f;
                AbstractC0448u.d((androidx.compose.foundation.lazy.layout.N) this.d, this.e, i, obj3, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.c | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.f;
                AbstractC0448u.b(this.d, this.b, (androidx.compose.foundation.lazy.layout.Z) this.e, dVar2, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Number) obj2).intValue();
                int iH4 = C0776c.H(this.b | 1);
                androidx.compose.runtime.internal.d dVar3 = (androidx.compose.runtime.internal.d) this.f;
                O3 o3 = (O3) this.e;
                Z1.l(o3, (androidx.compose.ui.q) this.d, dVar3, (InterfaceC0806l) obj, iH4, this.c);
                break;
            default:
                ((Number) obj2).intValue();
                int iH5 = C0776c.H(this.b | 1);
                Function1 function1 = (Function1) this.e;
                androidx.compose.ui.viewinterop.k.a(function1, (androidx.compose.ui.q) this.d, (Function1) this.f, (InterfaceC0806l) obj, iH5, this.c);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0419y(androidx.compose.ui.q qVar, androidx.compose.ui.i iVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = 0;
        this.d = qVar;
        this.e = iVar;
        this.f = dVar;
        this.b = i;
        this.c = i2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0419y(Object obj, int i, androidx.compose.foundation.lazy.layout.Z z, androidx.compose.runtime.internal.d dVar, int i2) {
        super(2);
        this.a = 2;
        this.d = obj;
        this.b = i;
        this.e = z;
        this.f = dVar;
        this.c = i2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0419y(Object obj, androidx.compose.ui.q qVar, InterfaceC4938g interfaceC4938g, int i, int i2, int i3) {
        super(2);
        this.a = i3;
        this.e = obj;
        this.d = qVar;
        this.f = interfaceC4938g;
        this.b = i;
        this.c = i2;
    }
}
