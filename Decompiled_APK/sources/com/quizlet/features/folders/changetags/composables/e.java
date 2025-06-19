package com.quizlet.features.folders.changetags.composables;

import android.os.Build;
import android.os.Bundle;
import androidx.activity.AbstractC0037i;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.generated.enums.y1;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ x j;
    public final /* synthetic */ kotlin.reflect.f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(x xVar, kotlin.reflect.f fVar, h hVar) {
        super(2, hVar);
        this.j = xVar;
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String string;
        Serializable serializable;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        x xVar = this.j;
        if (xVar.b()) {
            Bundle bundle = xVar.c;
            if (bundle == null || (string = bundle.getString("study_material_id")) == null) {
                throw new IllegalArgumentException("Required STUDY_MATERIAL_ID_MODAL_ARG is not present");
            }
            Bundle bundle2 = xVar.c;
            if (bundle2 != null) {
                if (Build.VERSION.SDK_INT >= 34) {
                    serializable = AbstractC0037i.e(bundle2);
                } else {
                    serializable = bundle2.getSerializable("study_material_type");
                    if (!y1.class.isInstance(serializable)) {
                        serializable = null;
                    }
                }
                y1 y1Var = (y1) serializable;
                if (y1Var != null) {
                    ((Function1) this.k).invoke(new com.quizlet.features.folders.changetags.data.b(string, y1Var));
                }
            }
            throw new IllegalArgumentException("Required STUDY_MATERIAL_TYPE_MODAL_ARG is not present");
        }
        return Unit.a;
    }
}
