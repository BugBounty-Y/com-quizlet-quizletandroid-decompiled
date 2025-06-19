package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.folders.composables.AbstractC4248d;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.e4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0612e4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0624g4 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0612e4(C0624g4 c0624g4, androidx.compose.ui.q qVar, boolean z, boolean z2, boolean z3, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        androidx.compose.runtime.internal.d dVar2 = AbstractC4248d.a;
        this.a = c0624g4;
        this.b = qVar;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = dVar;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.g | 1);
        androidx.compose.runtime.internal.d dVar = this.f;
        androidx.compose.runtime.internal.d dVar2 = AbstractC4248d.a;
        AbstractC0618f4.a(this.a, this.b, this.c, this.d, this.e, dVar, interfaceC0806l, iH);
        return Unit.a;
    }
}
