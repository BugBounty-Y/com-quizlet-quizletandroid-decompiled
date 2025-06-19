package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class c3 implements e3 {
    public final ArrayList a;

    public c3(Context context, b3 b3Var) {
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        b3Var.getClass();
        arrayList.add(new g3(context, b3Var));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.e3
    public final void a(com.quizlet.data.repository.explanations.myexplanations.a aVar) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((e3) it2.next()).a(aVar);
        }
    }
}
