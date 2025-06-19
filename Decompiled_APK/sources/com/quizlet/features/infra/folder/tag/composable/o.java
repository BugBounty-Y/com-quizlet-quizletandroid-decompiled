package com.quizlet.features.infra.folder.tag.composable;

import android.os.Bundle;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ x j;
    public final /* synthetic */ com.quizlet.features.infra.folder.tag.viewmodel.a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(x xVar, com.quizlet.features.infra.folder.tag.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = xVar;
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String[] stringArray;
        List listC;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        x xVar = this.j;
        if (xVar.b()) {
            Bundle bundle = xVar.c;
            if (bundle == null) {
                throw new IllegalArgumentException("NewTagModalArgs.ARG_PARENT_FOLDER_ID is required to show the modal");
            }
            long j = bundle.getLong("NewTagModalArgs.ARG_PARENT_FOLDER_ID");
            Bundle bundle2 = xVar.c;
            if (bundle2 == null || (stringArray = bundle2.getStringArray("NewTagModalArgs.ARG_CURRENT_FOLDER_TAGS")) == null || (listC = C4930v.c(stringArray)) == null) {
                throw new IllegalArgumentException("NewTagModalArgs.ARG_CURRENT_FOLDER_TAGS is required to show the modal");
            }
            ((com.quizlet.features.infra.folder.tag.viewmodel.d) this.k).A(new com.quizlet.features.infra.folder.tag.screenstates.e(j, listC));
        }
        return Unit.a;
    }
}
