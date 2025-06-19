package androidx.compose.foundation.contextmenu;

import androidx.compose.foundation.lazy.layout.l0;
import androidx.compose.foundation.text.N0;
import androidx.compose.foundation.text.selection.InterfaceC0533n;
import androidx.compose.foundation.text.selection.W;
import androidx.compose.material3.L3;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.e0;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.V;
import com.google.android.gms.internal.mlkit_vision_barcode.W5;
import java.util.Arrays;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2, Object obj, Object obj2, Object obj3) {
        super(2);
        this.a = i2;
        this.e = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = i;
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                ?? r3 = (r) this.c;
                V.a((o) this.e, (Function0) this.b, nVar, r3, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.d | 1);
                ?? r0 = (r) this.c;
                q.d((h) this.e, (Function0) this.b, r0, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.c;
                ((l0) this.e).e(this.b, dVar, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Number) obj2).intValue();
                Object[] objArr = (Object[]) this.b;
                Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
                int iH4 = C0776c.H(this.d | 1);
                ((N0) this.e).b(objArrCopyOf, (Function1) this.c, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Number) obj2).intValue();
                int iH5 = C0776c.H(this.d | 1);
                androidx.compose.ui.d dVar2 = (androidx.compose.ui.d) this.b;
                androidx.compose.runtime.internal.d dVar3 = (androidx.compose.runtime.internal.d) this.c;
                W.a((InterfaceC0533n) this.e, dVar2, dVar3, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Number) obj2).intValue();
                int iH6 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar4 = (androidx.compose.runtime.internal.d) this.c;
                Z1.f((L3) this.e, (androidx.compose.ui.q) this.b, dVar4, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Number) obj2).intValue();
                int iH7 = C0776c.H(this.d) | 1;
                Object obj3 = this.b;
                Object obj4 = this.c;
                ((androidx.compose.runtime.internal.d) this.e).d(obj3, obj4, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Number) obj2).intValue();
                int iH8 = C0776c.H(this.d | 1);
                Function2 function2 = (Function2) this.c;
                AbstractC0897s.d((e0) this.e, (androidx.compose.ui.q) this.b, function2, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Number) obj2).intValue();
                int iH9 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar5 = (androidx.compose.runtime.internal.d) this.c;
                W5.a((Function0) this.b, (androidx.compose.ui.window.r) this.e, dVar5, (InterfaceC0806l) obj, iH9);
                break;
            default:
                ((Number) obj2).intValue();
                androidx.compose.runtime.internal.d dVar6 = (androidx.compose.runtime.internal.d) this.c;
                androidx.glance.p pVar = (androidx.glance.p) this.e;
                M7.a(pVar, (androidx.glance.layout.c) this.b, dVar6, (InterfaceC0806l) obj, 385, this.d);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public a(h hVar, Function0 function0, Function1 function1, int i) {
        super(2);
        this.a = 1;
        this.e = hVar;
        this.b = function0;
        this.c = (r) function1;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public a(o oVar, Function0 function0, Function1 function1, int i) {
        super(2);
        this.a = 0;
        this.e = oVar;
        this.b = function0;
        this.c = (r) function1;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(androidx.glance.p pVar, androidx.glance.layout.c cVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = 9;
        this.e = pVar;
        this.b = cVar;
        this.c = dVar;
        this.d = i2;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Function0 function0, androidx.compose.ui.window.r rVar, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = 8;
        this.b = function0;
        this.e = rVar;
        this.c = dVar;
        this.d = i;
    }
}
