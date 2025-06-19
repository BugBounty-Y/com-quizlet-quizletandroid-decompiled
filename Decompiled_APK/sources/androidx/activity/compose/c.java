package androidx.activity.compose;

import androidx.compose.foundation.lazy.layout.L;
import androidx.compose.foundation.lazy.layout.Y;
import androidx.compose.foundation.lazy.layout.c0;
import androidx.compose.foundation.text.selection.U;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.material3.DialogC0671k2;
import androidx.compose.runtime.G;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.C0961p0;
import androidx.compose.ui.window.u;
import androidx.lifecycle.p0;
import com.facebook.FacebookException;
import com.facebook.internal.C1553h;
import com.facebook.login.B;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class c implements G {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.compose.runtime.G
    public final void dispose() {
        Unit unit;
        switch (this.a) {
            case 0:
                androidx.activity.result.g gVar = ((a) this.b).a;
                if (gVar != null) {
                    gVar.b();
                    unit = Unit.a;
                } else {
                    unit = null;
                }
                if (unit == null) {
                    throw new IllegalStateException("Launcher has not been initialized");
                }
                return;
            case 1:
                ((i) this.b).e();
                return;
            case 2:
                ((r) this.b).e();
                return;
            case 3:
                ((L) this.b).d = null;
                return;
            case 4:
                ((c0) this.b).c = null;
                return;
            case 5:
                Y y = (Y) this.b;
                int iA = y.a();
                for (int i = 0; i < iA; i++) {
                    y.c();
                }
                return;
            case 6:
                ((i0) this.b).m();
                return;
            case 7:
                U u = (U) this.b;
                u.i();
                ((L0) u.i).setValue(Boolean.FALSE);
                return;
            case 8:
                DialogC0671k2 dialogC0671k2 = (DialogC0671k2) this.b;
                dialogC0671k2.dismiss();
                dialogC0671k2.g.disposeComposition();
                return;
            case 9:
                ((C0961p0) this.b).a.invoke();
                return;
            case 10:
                androidx.compose.ui.window.s sVar = (androidx.compose.ui.window.s) this.b;
                sVar.dismiss();
                sVar.g.disposeComposition();
                return;
            case 11:
                u uVar = (u) this.b;
                uVar.disposeComposition();
                uVar.getClass();
                p0.n(uVar, null);
                uVar.f.removeViewImmediate(uVar);
                return;
            default:
                com.facebook.j jVar = (com.facebook.j) this.b;
                if (!(jVar instanceof C1553h)) {
                    throw new FacebookException("Unexpected CallbackManager, please use the provided Factory.");
                }
                ((C1553h) jVar).a.remove(Integer.valueOf(assistantMode.refactored.a.a(1)));
                return;
        }
    }

    public c(B b, com.facebook.j jVar) {
        this.a = 12;
        this.b = jVar;
    }
}
