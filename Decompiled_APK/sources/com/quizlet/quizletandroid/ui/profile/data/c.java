package com.quizlet.quizletandroid.ui.profile.data;

import androidx.lifecycle.Y;
import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.interactor.folderwithcreator.m;
import io.reactivex.rxjava3.subjects.r;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends com.quizlet.viewmodel.b {
    public final m c;
    public final r d;
    public AtomicReference e;
    public Long f;
    public boolean g;
    public final Y h;
    public final Y i;

    public c(m getFoldersWithCreatorUseCase) {
        Intrinsics.checkNotNullParameter(getFoldersWithCreatorUseCase, "getFoldersWithCreatorUseCase");
        this.c = getFoldersWithCreatorUseCase;
        this.d = Z.f("create(...)");
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.e = dVar;
        this.h = new Y();
        this.i = new Y(Boolean.FALSE);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    public final void B() {
        Long l = this.f;
        if (l == null) {
            throw new IllegalStateException("User ID must be set before refreshing data");
        }
        long jLongValue = l.longValue();
        boolean z = this.g;
        this.e.dispose();
        List listB = A.b(Long.valueOf(jLongValue));
        m mVar = this.c;
        r stopToken = this.d;
        io.reactivex.rxjava3.core.i iVarI = mVar.i(listB, stopToken);
        if (z) {
            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
            iVarI = io.reactivex.rxjava3.core.i.d(iVarI, ((androidx.work.impl.model.c) mVar.b).b(stopToken, new C1510p(mVar, jLongValue, 5)), new b(0));
            Intrinsics.checkNotNullExpressionValue(iVarI, "Observable.combineLatest…ombineFunction(t1, t2) })");
        }
        final int i = 0;
        final int i2 = 1;
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(iVarI, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.data.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i) {
                    case 0:
                        Throwable it2 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        this.b.i.j(Boolean.TRUE);
                        timber.log.c.a.c(it2, "Error fetching folders", new Object[0]);
                        break;
                    default:
                        List it3 = (List) obj;
                        Intrinsics.checkNotNullParameter(it3, "it");
                        c cVar = this.b;
                        cVar.h.j(it3);
                        cVar.i.j(Boolean.FALSE);
                        break;
                }
                return Unit.a;
            }
        }, null, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.data.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i2) {
                    case 0:
                        Throwable it2 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        this.b.i.j(Boolean.TRUE);
                        timber.log.c.a.c(it2, "Error fetching folders", new Object[0]);
                        break;
                    default:
                        List it3 = (List) obj;
                        Intrinsics.checkNotNullParameter(it3, "it");
                        c cVar = this.b;
                        cVar.h.j(it3);
                        cVar.i.j(Boolean.FALSE);
                        break;
                }
                return Unit.a;
            }
        }, 2);
        this.e = hVarD;
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        this.d.onSuccess(Unit.a);
        this.e.dispose();
        this.e = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
    }
}
