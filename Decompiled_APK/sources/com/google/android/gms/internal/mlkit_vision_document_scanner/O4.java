package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O4 {
    public static final /* synthetic */ int a = 0;

    public static final ArrayList a(NativeCustomFormatAd nativeCustomFormatAd) {
        Intrinsics.checkNotNullParameter(nativeCustomFormatAd, "<this>");
        ArrayList arrayList = new ArrayList();
        List list = com.quizlet.ads.viewmodel.a.k;
        Iterator it2 = com.quizlet.ads.viewmodel.a.k.iterator();
        while (it2.hasNext()) {
            CharSequence text = nativeCustomFormatAd.getText((String) it2.next());
            if (text != null) {
                arrayList.add(text.toString());
            }
        }
        return arrayList;
    }
}
