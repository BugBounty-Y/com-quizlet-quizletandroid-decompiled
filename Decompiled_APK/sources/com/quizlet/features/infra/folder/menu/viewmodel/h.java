package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ com.quizlet.data.interactor.folderstudymaterial.g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(m mVar, com.quizlet.data.interactor.folderstudymaterial.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            m mVar = this.k;
            FolderLogger folderLogger = mVar.b;
            com.quizlet.data.interactor.folderstudymaterial.g gVar = this.l;
            folderLogger.G(gVar.c(), gVar.b());
            this.j = 1;
            if (m.h(mVar, gVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
