package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.folders.data.C4308t0;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4329j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ N j;
    public final /* synthetic */ AddMaterialFolderData k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4329j(N n, AddMaterialFolderData addMaterialFolderData, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = n;
        this.k = addMaterialFolderData;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4329j(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4329j) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        N n = this.j;
        long j = n.s;
        com.quizlet.features.folders.logging.e eVar = n.h;
        eVar.getClass();
        EventLoggerExt.a(eVar.a, "folder_add_new_flashcard_set_click", new com.braze.requests.framework.m(10, j));
        n.A.h(new C4308t0(this.k));
        return Unit.a;
    }
}
