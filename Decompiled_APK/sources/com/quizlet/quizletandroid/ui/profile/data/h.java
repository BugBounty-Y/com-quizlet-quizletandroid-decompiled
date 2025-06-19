package com.quizlet.quizletandroid.ui.profile.data;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.firebase.messaging.p;
import com.quizlet.data.model.User;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.quizletandroid.ui.profile.q;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class h extends com.quizlet.viewmodel.a {
    public final com.quizlet.data.interactor.set.c d;
    public final UserInfoCache e;
    public final p f;
    public final com.quizlet.infra.legacysyncengine.managers.d g;
    public final com.quizlet.quizletandroid.braze.events.b h;
    public final com.quizlet.features.userprofile.a i;
    public final Y j;
    public final Y k;
    public final X l;
    public final X m;
    public long n;
    public boolean o;

    public h(com.quizlet.data.interactor.set.c getUserUseCase, UserInfoCache userInfoCache, p achievementsUseCase, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.quizletandroid.braze.events.b brazeViewScreenEventManager, com.quizlet.features.userprofile.a eventLogger) {
        Intrinsics.checkNotNullParameter(getUserUseCase, "getUserUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(achievementsUseCase, "achievementsUseCase");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(brazeViewScreenEventManager, "brazeViewScreenEventManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.d = getUserUseCase;
        this.e = userInfoCache;
        this.f = achievementsUseCase;
        this.g = loggedInUserManager;
        this.h = brazeViewScreenEventManager;
        this.i = eventLogger;
        this.j = new Y();
        this.k = new Y();
        this.l = new X(1);
        this.m = new X(1);
    }

    public final ArrayList B(boolean z, boolean z2) {
        q.b.getClass();
        ArrayList arrayListY0 = CollectionsKt.y0(B.j(q.d, q.f));
        if (z2 && C(this.n)) {
            arrayListY0.add(0, q.c);
        }
        if (!z) {
            arrayListY0.add(B.i(arrayListY0), q.e);
        }
        return arrayListY0;
    }

    public final boolean C(long j) {
        return j == this.e.getPersonId();
    }

    public final void D() {
        long j = this.n;
        com.quizlet.data.interactor.set.c cVar = this.d;
        cVar.getClass();
        r stopToken = this.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        C4887f c4887f = new C4887f(((androidx.work.impl.model.c) cVar.b).b(stopToken, new C1510p(cVar, j, 11)), 1);
        Intrinsics.checkNotNullExpressionValue(c4887f, "distinctUntilChanged(...)");
        final int i = 0;
        final int i2 = 1;
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(c4887f, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.data.d
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean z;
                boolean z2;
                switch (i) {
                    case 0:
                        Throwable it2 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        timber.log.c.a.q(it2, "Encountered error loading data", new Object[0]);
                        h hVar = this.b;
                        hVar.j.j(new i("", "", false, false, false, false));
                        hVar.k.j(K.a);
                        break;
                    default:
                        User it3 = (User) obj;
                        Intrinsics.checkNotNullParameter(it3, "it");
                        h hVar2 = this.b;
                        hVar2.getClass();
                        String str = it3.b;
                        boolean zB = hVar2.e.b();
                        boolean z3 = true;
                        boolean z4 = it3.e;
                        if (!zB || hVar2.C(hVar2.n) || z4) {
                            z = true;
                            z3 = false;
                            z2 = false;
                        } else {
                            z = true;
                            z2 = false;
                        }
                        boolean z5 = hVar2.o;
                        boolean z6 = z2;
                        boolean z7 = !z5;
                        if (it3.f == 0) {
                            z6 = z;
                        }
                        hVar2.j.j(new i(str, it3.i, z3, z5, z7, z6));
                        E.A(p0.j(hVar2), new e(hVar2, z4), null, new f(hVar2, z4, null), 2);
                        break;
                }
                return Unit.a;
            }
        }, null, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.data.d
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean z;
                boolean z2;
                switch (i2) {
                    case 0:
                        Throwable it2 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        timber.log.c.a.q(it2, "Encountered error loading data", new Object[0]);
                        h hVar = this.b;
                        hVar.j.j(new i("", "", false, false, false, false));
                        hVar.k.j(K.a);
                        break;
                    default:
                        User it3 = (User) obj;
                        Intrinsics.checkNotNullParameter(it3, "it");
                        h hVar2 = this.b;
                        hVar2.getClass();
                        String str = it3.b;
                        boolean zB = hVar2.e.b();
                        boolean z3 = true;
                        boolean z4 = it3.e;
                        if (!zB || hVar2.C(hVar2.n) || z4) {
                            z = true;
                            z3 = false;
                            z2 = false;
                        } else {
                            z = true;
                            z2 = false;
                        }
                        boolean z5 = hVar2.o;
                        boolean z6 = z2;
                        boolean z7 = !z5;
                        if (it3.f == 0) {
                            z6 = z;
                        }
                        hVar2.j.j(new i(str, it3.i, z3, z5, z7, z6));
                        E.A(p0.j(hVar2), new e(hVar2, z4), null, new f(hVar2, z4, null), 2);
                        break;
                }
                return Unit.a;
            }
        }, 2);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
    }
}
