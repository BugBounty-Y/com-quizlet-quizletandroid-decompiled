package org.wordpress.aztec.formatting;

import androidx.compose.animation.core.J0;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class n extends J0 {
    public final void T(ArrayList arrayList, Function0 function0) {
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            u().removeSpan(((m) it2.next()).a);
        }
        function0.invoke();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            m mVar = (m) it3.next();
            u().setSpan(mVar.a, mVar.b, mVar.c, mVar.d);
        }
    }
}
