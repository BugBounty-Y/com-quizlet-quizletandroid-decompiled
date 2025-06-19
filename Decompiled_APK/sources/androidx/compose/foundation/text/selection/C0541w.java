package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.runtime.L0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.selection.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0541w extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ U b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0541w(U u, int i) {
        super(1);
        this.a = i;
        this.b = u;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0535p c0535p;
        C0535p c0535p2;
        boolean z;
        switch (this.a) {
            case 0:
                return new androidx.activity.compose.c(this.b, 7);
            case 1:
                long jLongValue = ((Number) obj).longValue();
                U u = this.b;
                if (u.a.a().a(jLongValue)) {
                    u.o();
                    u.q();
                }
                return Unit.a;
            case 2:
                long jLongValue2 = ((Number) obj).longValue();
                U u2 = this.b;
                if (u2.a.a().a(jLongValue2)) {
                    u2.i();
                    u2.m(null);
                }
                return Unit.a;
            case 3:
                long jLongValue3 = ((Number) obj).longValue();
                U u3 = this.b;
                C0536q c0536qE = u3.e();
                if (c0536qE != null && (c0535p2 = c0536qE.a) != null && jLongValue3 == c0535p2.c) {
                    ((L0) u3.n).setValue(null);
                }
                C0536q c0536qE2 = u3.e();
                if (c0536qE2 != null && (c0535p = c0536qE2.b) != null && jLongValue3 == c0535p.c) {
                    ((L0) u3.o).setValue(null);
                }
                if (u3.a.a().a(jLongValue3)) {
                    u3.q();
                }
                return Unit.a;
            case 4:
                androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) obj;
                U u4 = this.b;
                u4.k = rVar;
                if (u4.d() && u4.e() != null) {
                    androidx.compose.ui.geometry.b bVar = rVar != null ? new androidx.compose.ui.geometry.b(rVar.d(0L)) : null;
                    if (!Intrinsics.b(u4.j, bVar)) {
                        u4.j = bVar;
                        u4.o();
                        u4.q();
                    }
                }
                return Unit.a;
            case 5:
                androidx.compose.ui.focus.s sVar = (androidx.compose.ui.focus.s) obj;
                boolean zA = sVar.a();
                U u5 = this.b;
                if (!zA && u5.d()) {
                    u5.i();
                }
                ((L0) u5.i).setValue(Boolean.valueOf(sVar.a()));
                return Unit.a;
            case 6:
                this.b.l(((Boolean) obj).booleanValue());
                return Unit.a;
            case 7:
                if (AbstractC0484d0.a.a(((androidx.compose.ui.input.key.b) obj).a) == 17) {
                    this.b.b();
                    z = true;
                } else {
                    z = false;
                }
                return Boolean.valueOf(z);
            default:
                this.b.m((C0536q) obj);
                return Unit.a;
        }
    }
}
