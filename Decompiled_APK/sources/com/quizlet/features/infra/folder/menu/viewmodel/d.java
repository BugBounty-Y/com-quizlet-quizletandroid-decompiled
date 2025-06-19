package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ long l;
    public final /* synthetic */ m m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(boolean z, long j, m mVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = j;
        this.m = mVar;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.quizlet.data.interactor.folderstudymaterial.g dVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            boolean z = this.k;
            long j = this.l;
            m mVar = this.m;
            if (z) {
                String str = mVar.m;
                if (str == null) {
                    Intrinsics.m("studyMaterialId");
                    throw null;
                }
                y1 y1Var = mVar.l;
                if (y1Var == null) {
                    Intrinsics.m("studyMaterialType");
                    throw null;
                }
                dVar = new com.quizlet.data.interactor.folderstudymaterial.f(j, str, y1Var);
            } else {
                String str2 = mVar.m;
                if (str2 == null) {
                    Intrinsics.m("studyMaterialId");
                    throw null;
                }
                y1 y1Var2 = mVar.l;
                if (y1Var2 == null) {
                    Intrinsics.m("studyMaterialType");
                    throw null;
                }
                dVar = new com.quizlet.data.interactor.folderstudymaterial.d(j, str2, y1Var2);
            }
            FolderLogger folderLogger = mVar.b;
            String str3 = mVar.m;
            if (str3 == null) {
                Intrinsics.m("studyMaterialId");
                throw null;
            }
            y1 y1Var3 = mVar.l;
            if (y1Var3 == null) {
                Intrinsics.m("studyMaterialType");
                throw null;
            }
            folderLogger.D(this.l, str3, y1Var3, this.k);
            this.j = 1;
            if (m.a(mVar, this.n, dVar, this) == aVar) {
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
