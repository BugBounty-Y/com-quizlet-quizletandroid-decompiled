package com.quizlet.remote.model.folder.course;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.RecommendedStudyMaterial;
import com.quizlet.generated.enums.x1;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.remote.mapper.base.a {
    @Override // com.quizlet.remote.mapper.base.a
    public final Object c(Object obj) {
        RemoteRecommendedStudyMaterialModel remote = (RemoteRecommendedStudyMaterialModel) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        x1 x1Var = y1.Companion;
        Integer num = remote.b;
        if (num == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = num.intValue();
        x1Var.getClass();
        y1 y1VarA = x1.a(iIntValue);
        String str = remote.c;
        if (str == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Integer num2 = remote.d;
        return new RecommendedStudyMaterial(str, y1VarA, num2 != null ? num2.intValue() : 0, remote.e != null);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return S.f(this, list);
    }
}
