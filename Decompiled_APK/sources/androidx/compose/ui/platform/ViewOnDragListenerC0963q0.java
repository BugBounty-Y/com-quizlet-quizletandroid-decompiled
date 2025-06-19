package androidx.compose.ui.platform;

import android.view.DragEvent;
import android.view.View;
import androidx.collection.C0204b;
import androidx.collection.C0209g;
import androidx.compose.ui.node.AbstractC0910f;

/* renamed from: androidx.compose.ui.platform.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ViewOnDragListenerC0963q0 implements View.OnDragListener, androidx.compose.ui.draganddrop.b {
    public final androidx.compose.ui.draganddrop.e a = new androidx.compose.ui.draganddrop.e();
    public final C0209g b = new C0209g(0);
    public final DragAndDropModifierOnDragListener$modifier$1 c = new androidx.compose.ui.node.T() { // from class: androidx.compose.ui.platform.DragAndDropModifierOnDragListener$modifier$1
        public final boolean equals(Object obj) {
            return obj == this;
        }

        public final int hashCode() {
            return this.b.a.hashCode();
        }

        @Override // androidx.compose.ui.node.T
        public final androidx.compose.ui.p l() {
            return this.b.a;
        }

        @Override // androidx.compose.ui.node.T
        public final /* bridge */ /* synthetic */ void n(androidx.compose.ui.p pVar) {
        }
    };

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // android.view.View.OnDragListener
    public final boolean onDrag(View view, DragEvent dragEvent) {
        com.google.android.gms.internal.instantapps.a aVar = new com.google.android.gms.internal.instantapps.a(dragEvent, 10);
        int action = dragEvent.getAction();
        androidx.compose.ui.draganddrop.e eVar = this.a;
        androidx.compose.ui.node.p0 p0Var = androidx.compose.ui.node.p0.a;
        switch (action) {
            case 1:
                kotlin.jvm.internal.F f = new kotlin.jvm.internal.F();
                androidx.compose.foundation.C c = new androidx.compose.foundation.C(aVar, eVar, f);
                if (c.invoke(eVar) == p0Var) {
                    AbstractC0910f.z(eVar, c);
                }
                boolean z = f.a;
                C0209g c0209g = this.b;
                c0209g.getClass();
                C0204b c0204b = new C0204b(c0209g);
                while (c0204b.hasNext()) {
                    ((androidx.compose.ui.draganddrop.e) c0204b.next()).Q0(aVar);
                }
                return z;
            case 2:
                eVar.P0(aVar);
                return false;
            case 3:
                return eVar.M0(aVar);
            case 4:
                androidx.compose.ui.draganddrop.d dVar = new androidx.compose.ui.draganddrop.d(aVar, 0);
                if (dVar.invoke(eVar) == p0Var) {
                    AbstractC0910f.z(eVar, dVar);
                    return false;
                }
                return false;
            case 5:
                eVar.N0(aVar);
                return false;
            case 6:
                eVar.O0(aVar);
                return false;
            default:
                return false;
        }
    }
}
