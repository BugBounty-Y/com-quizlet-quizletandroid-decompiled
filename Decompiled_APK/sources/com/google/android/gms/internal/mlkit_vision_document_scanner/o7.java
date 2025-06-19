package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class o7 implements n7 {
    public final ArrayList a;

    public o7(Context context, m7 m7Var) {
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        m7Var.getClass();
        arrayList.add(new q7(context, m7Var));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.n7
    public final void a(com.quizlet.data.repository.widget.b bVar) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((n7) it2.next()).a(bVar);
        }
    }
}
