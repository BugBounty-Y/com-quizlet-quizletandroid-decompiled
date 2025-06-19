package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.x1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0756x1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ int d;
    public final /* synthetic */ InterfaceC4938g e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0756x1(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.ui.text.L l, long j, long j2, int i) {
        super(2);
        this.e = dVar;
        this.f = dVar2;
        this.g = dVar3;
        this.h = l;
        this.b = j;
        this.c = j2;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Object obj3 = this.f;
        Object obj4 = this.h;
        Object obj5 = this.g;
        InterfaceC4938g interfaceC4938g = this.e;
        int i = this.d;
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(i | 1);
                androidx.compose.runtime.internal.d dVar = com.quizlet.upgrade.confirmation.composables.b.a;
                long j = this.c;
                C0717s1 c0717s1 = (C0717s1) obj4;
                AbstractC0762y1.a((Function0) interfaceC4938g, (androidx.compose.ui.q) obj3, (androidx.compose.ui.graphics.V) obj5, this.b, j, c0717s1, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(i | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) obj3;
                T3.b((androidx.compose.runtime.internal.d) interfaceC4938g, dVar2, (androidx.compose.runtime.internal.d) obj5, (androidx.compose.ui.text.L) obj4, this.b, this.c, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0756x1(Function0 function0, androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, long j2, C0717s1 c0717s1, int i) {
        super(2);
        androidx.compose.runtime.internal.d dVar = com.quizlet.upgrade.confirmation.composables.b.a;
        this.e = function0;
        this.f = qVar;
        this.g = v;
        this.b = j;
        this.c = j2;
        this.h = c0717s1;
        this.d = i;
    }
}
