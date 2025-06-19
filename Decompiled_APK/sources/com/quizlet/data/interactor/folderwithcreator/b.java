package com.quizlet.data.interactor.folderwithcreator;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.library.LibraryClassesException;
import com.quizlet.data.exceptions.library.LibraryFoldersException;
import com.quizlet.data.exceptions.library.LibraryStudySetsException;
import java.io.IOException;
import kotlin.Unit;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public /* synthetic */ Throwable k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) throws LibraryClassesException, LibraryFoldersException, LibraryStudySetsException {
        Throwable th = (Throwable) obj2;
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (this.j) {
            case 0:
                b bVar = new b(3, 0, hVar);
                bVar.k = th;
                bVar.invokeSuspend(Unit.a);
                throw null;
            case 1:
                b bVar2 = new b(3, 1, hVar);
                bVar2.k = th;
                bVar2.invokeSuspend(Unit.a);
                throw null;
            case 2:
                b bVar3 = new b(3, 2, hVar);
                bVar3.k = th;
                return bVar3.invokeSuspend(Unit.a);
            case 3:
                b bVar4 = new b(3, 3, hVar);
                bVar4.k = th;
                bVar4.invokeSuspend(Unit.a);
                throw null;
            case 4:
                b bVar5 = new b(3, 4, hVar);
                bVar5.k = th;
                bVar5.invokeSuspend(Unit.a);
                throw null;
            case 5:
                b bVar6 = new b(3, 5, hVar);
                bVar6.k = th;
                return bVar6.invokeSuspend(Unit.a);
            case 6:
                b bVar7 = new b(3, 6, hVar);
                bVar7.k = th;
                return bVar7.invokeSuspend(Unit.a);
            case 7:
                b bVar8 = new b(3, 7, hVar);
                bVar8.k = th;
                return bVar8.invokeSuspend(Unit.a);
            case 8:
                b bVar9 = new b(3, 8, hVar);
                bVar9.k = th;
                return bVar9.invokeSuspend(Unit.a);
            case 9:
                b bVar10 = new b(3, 9, hVar);
                bVar10.k = th;
                return bVar10.invokeSuspend(Unit.a);
            default:
                b bVar11 = new b(3, 10, hVar);
                bVar11.k = th;
                return bVar11.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws LibraryClassesException, LibraryFoldersException, LibraryStudySetsException {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                throw new LibraryFoldersException(this.k);
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                throw new LibraryFoldersException(this.k);
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                Throwable th = this.k;
                if (th instanceof IOException) {
                    timber.log.c.a.e(th);
                }
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                throw new LibraryClassesException(this.k);
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                throw new LibraryStudySetsException(this.k);
            case 5:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.e(this.k);
                return Unit.a;
            case 6:
                kotlin.coroutines.intrinsics.a aVar7 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.e(this.k);
                return Unit.a;
            case 7:
                kotlin.coroutines.intrinsics.a aVar8 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.e(this.k);
                return Unit.a;
            case 8:
                kotlin.coroutines.intrinsics.a aVar9 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.e(this.k);
                return Unit.a;
            case 9:
                kotlin.coroutines.intrinsics.a aVar10 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.e(this.k);
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar11 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                timber.log.c.a.b(this.k);
                return Unit.a;
        }
    }
}
