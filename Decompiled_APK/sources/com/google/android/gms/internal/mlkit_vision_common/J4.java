package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class J4 implements I4 {
    public final ArrayList a;

    public J4(Context context, H4 h4) {
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        h4.getClass();
        arrayList.add(new L4(context, h4));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.I4
    public final void a(com.quizlet.data.repository.qclass.c cVar) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((I4) it2.next()).a(cVar);
        }
    }
}
