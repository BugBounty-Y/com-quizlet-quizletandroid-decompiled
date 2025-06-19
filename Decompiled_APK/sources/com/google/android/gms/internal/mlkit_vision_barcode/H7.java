package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.appcompat.widget.C0122z;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class H7 implements G7 {
    public final ArrayList a;

    public H7(Context context, F7 f7) {
        ArrayList arrayList = new ArrayList();
        this.a = arrayList;
        f7.getClass();
        arrayList.add(new L7(context, f7));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.G7
    public final void a(C0122z c0122z) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((G7) it2.next()).a(c0122z);
        }
    }
}
