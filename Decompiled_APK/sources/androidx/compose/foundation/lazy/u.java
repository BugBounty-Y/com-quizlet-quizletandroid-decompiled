package androidx.compose.foundation.lazy;

import androidx.appcompat.widget.C0070a;
import androidx.compose.foundation.lazy.layout.a0;
import androidx.compose.foundation.lazy.layout.c0;
import androidx.compose.foundation.lazy.layout.d0;
import androidx.compose.foundation.lazy.layout.o0;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import java.util.Collection;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class u extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(int i, Collection collection) {
        super(1);
        this.a = 3;
        this.b = i;
        this.c = collection;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                a0 a0Var = (a0) obj;
                C0070a c0070a = ((A) this.c).a;
                androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
                androidx.compose.runtime.snapshots.r.g(hVarD, androidx.compose.runtime.snapshots.r.e(hVarD), hVarD != null ? hVarD.e() : null);
                for (int i = 0; i < 2; i++) {
                    int i2 = this.b + i;
                    a0Var.getClass();
                    long j = d0.a;
                    c0 c0Var = a0Var.b;
                    com.quizlet.data.interactor.set.c cVar = c0Var.c;
                    if (cVar != null) {
                        a0Var.a.add(new o0(cVar, i2, j, c0Var.b));
                    }
                }
                break;
            case 1:
                a0 a0Var2 = (a0) obj;
                C0070a c0070a2 = ((androidx.compose.foundation.lazy.grid.A) this.c).a;
                androidx.compose.runtime.snapshots.h hVarD2 = androidx.compose.runtime.snapshots.r.d();
                androidx.compose.runtime.snapshots.r.g(hVarD2, androidx.compose.runtime.snapshots.r.e(hVarD2), hVarD2 != null ? hVarD2.e() : null);
                int i3 = 0;
                while (true) {
                    c0070a2.getClass();
                    if (i3 >= 2) {
                        break;
                    } else {
                        int i4 = this.b + i3;
                        a0Var2.getClass();
                        long j2 = d0.a;
                        c0 c0Var2 = a0Var2.b;
                        com.quizlet.data.interactor.set.c cVar2 = c0Var2.c;
                        if (cVar2 != null) {
                            a0Var2.a.add(new o0(cVar2, i4, j2, c0Var2.b));
                        }
                        i3++;
                    }
                }
            case 2:
                V.d((V) obj, (W) this.c, 0, -this.b);
                break;
            case 3:
                break;
            case 4:
                Boolean boolF = androidx.compose.ui.focus.a.F((androidx.compose.ui.focus.t) obj, this.b);
                ((J) this.c).a = boolF;
                break;
            case 5:
                androidx.sqlite.db.f it2 = (androidx.sqlite.db.f) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                int i5 = this.b;
                Long l = (Long) this.c;
                int i6 = i5 + 1;
                if (l == null) {
                    it2.R(i6);
                } else {
                    it2.z(i6, l.longValue());
                }
                break;
            default:
                androidx.sqlite.db.f it3 = (androidx.sqlite.db.f) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                int i7 = this.b;
                String str = (String) this.c;
                int i8 = i7 + 1;
                if (str == null) {
                    it3.R(i8);
                } else {
                    it3.g(i8, str);
                }
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ u(Object obj, int i, int i2) {
        super(1);
        this.a = i2;
        this.c = obj;
        this.b = i;
    }
}
