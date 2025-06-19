package androidx.compose.animation;

import android.os.Bundle;
import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.K0;
import androidx.compose.material3.L1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import java.io.Serializable;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ InterfaceC4938g c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.runtime.internal.d dVar5, int i) {
        super(2);
        this.a = 2;
        this.c = dVar;
        this.e = dVar2;
        this.f = dVar3;
        this.b = dVar4;
        this.g = dVar5;
        this.d = i;
    }

    /* JADX WARN: Type inference failed for: r5v7, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.c;
                Boolean bool = (Boolean) this.e;
                K0 k0 = (K0) this.b;
                E.j(bool, (androidx.compose.ui.n) this.f, k0, (String) this.g, dVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.c;
                E.i((E0) this.e, (androidx.compose.ui.q) this.f, (K0) this.b, (C0229c) this.g, dVar2, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar3 = (androidx.compose.runtime.internal.d) this.f;
                L1.b((androidx.compose.runtime.internal.d) this.c, (androidx.compose.runtime.internal.d) this.e, dVar3, (androidx.compose.runtime.internal.d) this.b, (androidx.compose.runtime.internal.d) this.g, (InterfaceC0806l) obj, iH3);
                break;
            default:
                ((Number) obj2).intValue();
                int iH4 = C0776c.H(this.d | 1);
                ?? r5 = (kotlin.jvm.internal.r) this.c;
                AbstractC3153g7.a((Class) this.e, (androidx.compose.ui.q) this.f, (androidx.fragment.compose.e) this.b, (Bundle) this.g, r5, (InterfaceC0806l) obj, iH4);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public K(Class cls, androidx.compose.ui.q qVar, androidx.fragment.compose.e eVar, Bundle bundle, Function1 function1, int i) {
        super(2);
        this.a = 3;
        this.e = cls;
        this.f = qVar;
        this.b = eVar;
        this.g = bundle;
        this.c = (kotlin.jvm.internal.r) function1;
        this.d = i;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ K(Object obj, androidx.compose.ui.q qVar, K0 k0, Serializable serializable, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = i2;
        this.e = obj;
        this.f = qVar;
        this.b = k0;
        this.g = serializable;
        this.c = dVar;
        this.d = i;
    }
}
