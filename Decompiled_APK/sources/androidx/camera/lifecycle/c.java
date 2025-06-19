package androidx.camera.lifecycle;

import androidx.lifecycle.A;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1238a0;
import androidx.lifecycle.J;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes.dex */
public final class c implements I {
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g a;
    public final J b;

    public c(J j, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar) {
        this.b = j;
        this.a = gVar;
    }

    @InterfaceC1238a0(A.ON_DESTROY)
    public void onDestroy(J j) {
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.a;
        synchronized (gVar.b) {
            try {
                c cVarK = gVar.k(j);
                if (cVarK == null) {
                    return;
                }
                gVar.u(j);
                Iterator it2 = ((Set) ((HashMap) gVar.d).get(cVarK)).iterator();
                while (it2.hasNext()) {
                    ((HashMap) gVar.c).remove((a) it2.next());
                }
                ((HashMap) gVar.d).remove(cVarK);
                cVarK.b.getLifecycle().b(cVarK);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @InterfaceC1238a0(A.ON_START)
    public void onStart(J j) {
        this.a.t(j);
    }

    @InterfaceC1238a0(A.ON_STOP)
    public void onStop(J j) {
        this.a.u(j);
    }
}
