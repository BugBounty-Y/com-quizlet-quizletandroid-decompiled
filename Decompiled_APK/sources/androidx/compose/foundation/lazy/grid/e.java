package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.gestures.C0343p;
import androidx.compose.foundation.layout.A0;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.material3.V;
import androidx.compose.material3.Y;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ InterfaceC4938g i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ Object l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(C0426a c0426a, androidx.compose.ui.q qVar, A a, A0 a0, InterfaceC0394k interfaceC0394k, InterfaceC0388h interfaceC0388h, C0343p c0343p, boolean z, Function1 function1, int i, int i2) {
        super(2);
        this.l = c0426a;
        this.b = qVar;
        this.c = a;
        this.d = a0;
        this.g = interfaceC0394k;
        this.h = interfaceC0388h;
        this.e = c0343p;
        this.f = z;
        this.i = function1;
        this.j = i;
        this.k = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.j | 1);
                C0426a c0426a = (C0426a) this.l;
                C0343p c0343p = (C0343p) this.e;
                AbstractC3155h0.b(c0426a, this.b, (A) this.c, (A0) this.d, (InterfaceC0394k) this.g, (InterfaceC0388h) this.h, c0343p, this.f, (Function1) this.i, (InterfaceC0806l) obj, iH, this.k);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.j | 1);
                int iH3 = C0776c.H(this.k);
                boolean z = this.f;
                InterfaceC0394k interfaceC0394k = (InterfaceC0394k) this.g;
                AbstractC3164i0.b(this.b, (A) this.c, (C0428c) this.l, (A0) this.d, (C0343p) this.e, z, interfaceC0394k, (InterfaceC0388h) this.h, (Function1) this.i, (InterfaceC0806l) obj, iH2, iH3);
                break;
            default:
                ((Number) obj2).intValue();
                int iH4 = C0776c.H(this.j | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.i;
                V v = (V) this.d;
                C0555x c0555x = (C0555x) this.h;
                Z1.d((Function0) this.l, this.b, this.f, (androidx.compose.ui.graphics.V) this.c, v, (Y) this.g, c0555x, (androidx.compose.foundation.interaction.l) this.e, dVar, (InterfaceC0806l) obj, iH4, this.k);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(androidx.compose.ui.q qVar, A a, C0428c c0428c, A0 a0, C0343p c0343p, boolean z, InterfaceC0394k interfaceC0394k, InterfaceC0388h interfaceC0388h, Function1 function1, int i, int i2) {
        super(2);
        this.b = qVar;
        this.c = a;
        this.l = c0428c;
        this.d = a0;
        this.e = c0343p;
        this.f = z;
        this.g = interfaceC0394k;
        this.h = interfaceC0388h;
        this.i = function1;
        this.j = i;
        this.k = i2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function0 function0, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.graphics.V v, V v2, Y y, C0555x c0555x, androidx.compose.foundation.interaction.l lVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.l = function0;
        this.b = qVar;
        this.f = z;
        this.c = v;
        this.d = v2;
        this.g = y;
        this.h = c0555x;
        this.e = lVar;
        this.i = dVar;
        this.j = i;
        this.k = i2;
    }
}
