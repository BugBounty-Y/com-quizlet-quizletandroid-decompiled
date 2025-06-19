package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.types.test.TestSettings;
import assistantMode.utils.AssistantValidationError;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class h3 {
    public static com.google.android.gms.internal.mlkit_common.r a;
    public static final /* synthetic */ int b = 0;

    public static final ArrayList a(assistantMode.enums.k kVar) {
        ArrayList arrayListK = kotlin.collections.B.k(kVar);
        while (kVar != W4.b(kVar)) {
            arrayListK.add(W4.b(kVar));
            kVar = W4.b(kVar);
        }
        return arrayListK;
    }

    public static final boolean b(List list, Map map) {
        if (list != null && list.isEmpty()) {
            return true;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Boolean bool = (Boolean) map.get((assistantMode.enums.k) it2.next());
            if (!(bool != null ? bool.booleanValue() : false)) {
                return false;
            }
        }
        return true;
    }

    public static final void c(TestSettings testSettings) {
        Intrinsics.checkNotNullParameter(testSettings, "testSettings");
        for (assistantMode.enums.k kVar : testSettings.a) {
            if (!test.utils.f.a.contains(kVar)) {
                throw new AssistantValidationError("Unrecognized question type: " + kVar);
            }
        }
    }
}
