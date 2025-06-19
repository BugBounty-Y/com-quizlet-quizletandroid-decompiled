package androidx.paging.compose;

import android.os.Build;
import android.util.Log;
import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.Z;
import androidx.datastore.core.C1086s;
import androidx.paging.A;
import androidx.paging.C1325l;
import androidx.paging.C1345v0;
import androidx.paging.C1351y0;
import androidx.paging.F;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.a0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class d {
    public final InterfaceC4992i a;
    public final CoroutineContext b;
    public final c c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;

    public d(InterfaceC4992i flow) {
        Intrinsics.checkNotNullParameter(flow, "flow");
        this.a = flow;
        CoroutineContext coroutineContext = (CoroutineContext) Z.l.getValue();
        this.b = coroutineContext;
        c cVar = new c(this, coroutineContext, flow instanceof a0 ? (C1351y0) CollectionsKt.firstOrNull(((a0) flow).a()) : null);
        this.c = cVar;
        this.d = C0776c.z(cVar.b());
        C1325l c1325l = (C1325l) ((s0) cVar.k.a).getValue();
        if (c1325l == null) {
            F f = i.a;
            c1325l = new C1325l(f.a, f.b, f.c, f, null);
        }
        this.e = C0776c.z(c1325l);
    }

    public final Object a(kotlin.coroutines.jvm.internal.i iVar) throws Throwable {
        this.c.k.b(new C1086s(new C0496b(this, 7), 29), iVar);
        return kotlin.coroutines.intrinsics.a.a;
    }

    public final Object b(int i) {
        Object value;
        Object value2;
        c cVar = this.c;
        s0 s0Var = cVar.j;
        do {
            value = s0Var.getValue();
            ((Boolean) value).getClass();
        } while (!s0Var.k(value, Boolean.TRUE));
        cVar.h = true;
        cVar.i = i;
        if (Build.ID != null && Log.isLoggable("Paging", 2)) {
            String message = "Accessing item index[" + i + ']';
            Intrinsics.checkNotNullParameter(message, "message");
        }
        com.google.firebase.platforminfo.c cVar2 = cVar.b;
        if (cVar2 != null) {
            cVar2.g(cVar.d.a(i));
        }
        C1345v0 c1345v0 = cVar.d;
        if (i < 0) {
            c1345v0.getClass();
        } else if (i < c1345v0.e()) {
            int i2 = i - c1345v0.c;
            if (i2 >= 0 && i2 < c1345v0.b) {
                c1345v0.b(i2);
            }
            s0 s0Var2 = cVar.j;
            do {
                value2 = s0Var2.getValue();
                ((Boolean) value2).getClass();
            } while (!s0Var2.k(value2, Boolean.FALSE));
            return ((A) ((L0) this.d).getValue()).get(i);
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index: ", ", Size: ");
        sbV.append(c1345v0.e());
        throw new IndexOutOfBoundsException(sbV.toString());
    }

    public final int c() {
        return ((A) ((L0) this.d).getValue()).a();
    }
}
