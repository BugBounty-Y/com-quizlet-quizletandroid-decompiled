package com.quizlet.remote.model.folder;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.folder.FailedToCopyFolderException;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderResponse;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public long j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ p m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(p pVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = pVar;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.m, this.n, hVar);
        gVar.l = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        p pVar;
        long j;
        FolderResponse folderResponse;
        FolderResponse.Models models;
        List list;
        RemoteFolder remoteFolder;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                p pVar2 = this.m;
                long j2 = this.n;
                kotlin.p pVar3 = r.b;
                com.quizlet.login.authentication.login.a aVar2 = pVar2.a;
                this.l = pVar2;
                this.j = j2;
                this.k = 1;
                Object objE = aVar2.e(j2, this);
                if (objE == aVar) {
                    return aVar;
                }
                pVar = pVar2;
                obj = objE;
                j = j2;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                j = this.j;
                pVar = (p) this.l;
                Z.e(obj);
            }
            folderResponse = (FolderResponse) ((ApiThreeWrapper) obj).a();
        } catch (Throwable th) {
            kotlin.p pVar4 = r.b;
            objB = Z.b(th);
        }
        if (folderResponse != null && (models = folderResponse.d) != null && (list = models.a) != null && (remoteFolder = (RemoteFolder) CollectionsKt.firstOrNull(list)) != null) {
            objB = pVar.b.g(remoteFolder);
            kotlin.p pVar5 = r.b;
            return new r(objB);
        }
        throw new FailedToCopyFolderException("Failed to copy folder with id (" + j + ")", null);
    }
}
