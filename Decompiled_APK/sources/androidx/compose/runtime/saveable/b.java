package androidx.compose.runtime.saveable;

import androidx.compose.animation.core.K;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.runtime.V;
import androidx.compose.runtime.snapshots.o;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;

/* loaded from: classes.dex */
public final class b implements InterfaceC0834w0 {
    public l a;
    public i b;
    public String c;
    public Object d;
    public Object[] e;
    public h f;
    public final K g = new K(this, 26);

    public b(l lVar, i iVar, String str, Object obj, Object[] objArr) {
        this.a = lVar;
        this.b = iVar;
        this.c = str;
        this.d = obj;
        this.e = objArr;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        h hVar = this.f;
        if (hVar != null) {
            ((com.quizlet.data.repository.course.membership.c) hVar).q();
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        h hVar = this.f;
        if (hVar != null) {
            ((com.quizlet.data.repository.course.membership.c) hVar).q();
        }
    }

    public final void c() throws Throwable {
        String strB;
        i iVar = this.b;
        if (this.f != null) {
            throw new IllegalArgumentException(("entry(" + this.f + ") is not null").toString());
        }
        if (iVar != null) {
            K k = this.g;
            Object objInvoke = k.invoke();
            if (objInvoke == null || iVar.a(objInvoke)) {
                this.f = iVar.d(this.c, k);
                return;
            }
            if (objInvoke instanceof o) {
                o oVar = (o) objInvoke;
                if (oVar.d() == V.c || oVar.d() == V.f || oVar.d() == V.d) {
                    strB = "MutableState containing " + oVar.getValue() + " cannot be saved using the current SaveableStateRegistry. The default implementation only supports types which can be stored inside the Bundle. Please consider implementing a custom Saver for this class and pass it as a stateSaver parameter to rememberSaveable().";
                } else {
                    strB = "If you use a custom SnapshotMutationPolicy for your MutableState you have to write a custom Saver";
                }
            } else {
                strB = L4.b(objInvoke);
            }
            throw new IllegalArgumentException(strB);
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() throws Throwable {
        c();
    }
}
