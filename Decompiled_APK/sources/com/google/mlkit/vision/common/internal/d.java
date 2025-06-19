package com.google.mlkit.vision.common.internal;

import android.util.Log;
import androidx.camera.camera2.internal.c0;
import com.google.firebase.components.q;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class d implements com.google.android.gms.tasks.c, com.google.firebase.components.d {
    public static final /* synthetic */ d a = new d();
    public static final /* synthetic */ d b = new d();

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        Set setC = c0Var.c(q.a(c.class));
        d dVar = new d();
        new HashMap();
        new HashMap();
        Iterator it2 = setC.iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        return dVar;
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        com.quizlet.data.repository.widget.b bVar = b.e;
        if (Log.isLoggable((String) bVar.b, 6)) {
            Log.e("MobileVisionBase", bVar.t("Error preloading model resource"), exc);
        }
    }
}
