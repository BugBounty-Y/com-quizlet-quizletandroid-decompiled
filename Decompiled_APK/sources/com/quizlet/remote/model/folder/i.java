package com.quizlet.remote.model.folder;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderResponse;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public final /* synthetic */ long m;
    public final /* synthetic */ List n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(p pVar, long j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = pVar;
        this.m = j;
        this.n = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.l, this.m, this.n, hVar);
        iVar.k = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        p pVar;
        FolderResponse.Models models;
        List remotes;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                p pVar2 = this.l;
                long j = this.m;
                List list = this.n;
                kotlin.p pVar3 = r.b;
                com.quizlet.login.authentication.login.a aVar2 = pVar2.a;
                this.k = pVar2;
                this.j = 1;
                Object objF = aVar2.f(j, list, this);
                if (objF == aVar) {
                    return aVar;
                }
                pVar = pVar2;
                obj = objF;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                pVar = (p) this.k;
                Z.e(obj);
            }
            FolderResponse folderResponse = (FolderResponse) ((ApiThreeWrapper) obj).a();
            if (folderResponse == null || (models = folderResponse.d) == null || (remotes = models.a) == null) {
                objB = K.a;
            } else {
                com.quizlet.quizletandroid.ui.folder.logging.a aVar3 = pVar.b;
                Intrinsics.checkNotNullParameter(remotes, "remotes");
                objB = S.f(aVar3, remotes);
            }
            kotlin.p pVar4 = r.b;
        } catch (Throwable th) {
            kotlin.p pVar5 = r.b;
            objB = Z.b(th);
        }
        return new r(objB);
    }
}
