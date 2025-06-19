package com.quizlet.features.folders.edittags.composables;

import android.os.Bundle;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ x j;
    public final /* synthetic */ com.quizlet.features.folders.edittags.viewmodel.c k;
    public final /* synthetic */ kotlinx.collections.immutable.e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(x xVar, com.quizlet.features.folders.edittags.viewmodel.c cVar, kotlinx.collections.immutable.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = xVar;
        this.k = cVar;
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String string;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        x xVar = this.j;
        if (xVar.b()) {
            Bundle bundle = xVar.c;
            if (bundle == null) {
                throw new IllegalArgumentException("Required ARG_EDIT_TAG_ID is not present");
            }
            long j = bundle.getLong("edit_tag_id");
            Bundle bundle2 = xVar.c;
            if (bundle2 == null || (string = bundle2.getString("edit_tag_label")) == null) {
                string = "";
            }
            this.k.A(new com.quizlet.features.folders.edittags.data.a(j, string, this.l));
        }
        return Unit.a;
    }
}
