package com.quizlet.remote.model.course;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.exceptions.folder.CourseAlreadyInFolderException;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderResponse;
import com.quizlet.remote.model.folder.course.SaveCourseToFolderRequestBody;
import com.quizlet.remote.service.InterfaceC4780g;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.HttpException;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.interactor.set.c k;
    public final /* synthetic */ long l;
    public final /* synthetic */ long m;
    public final /* synthetic */ long n;
    public final /* synthetic */ boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.interactor.set.c cVar, long j, long j2, long j3, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = j;
        this.m = j2;
        this.n = j3;
        this.o = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        List list;
        FolderResponse.Models models;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.interactor.set.c cVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                InterfaceC4780g interfaceC4780g = (InterfaceC4780g) cVar.a;
                long j = this.l;
                SaveCourseToFolderRequestBody saveCourseToFolderRequestBody = new SaveCourseToFolderRequestBody(this.m, this.n, this.o);
                this.j = 1;
                obj = interfaceC4780g.a(j, saveCourseToFolderRequestBody, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            com.quizlet.quizletandroid.ui.folder.logging.a aVar2 = (com.quizlet.quizletandroid.ui.folder.logging.a) cVar.b;
            FolderResponse folderResponse = (FolderResponse) ((ApiThreeWrapper) obj).a();
            if (folderResponse == null || (models = folderResponse.d) == null || (list = models.a) == null) {
                list = K.a;
            }
            return (AbstractC4119d0) CollectionsKt.firstOrNull(T.f(aVar2, list));
        } catch (HttpException e) {
            if (e.a == 409) {
                throw new CourseAlreadyInFolderException();
            }
            throw e;
        }
    }
}
