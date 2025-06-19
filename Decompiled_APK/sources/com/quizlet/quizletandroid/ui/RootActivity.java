package com.quizlet.quizletandroid.ui;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.appcompat.app.C0054j;
import androidx.camera.camera2.internal.c0;
import androidx.lifecycle.p0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3689o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.crashlytics.internal.common.q;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.data.model.m2;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.pushnotifications.FirebaseMessagePayload;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.EnumC4495k0;
import com.quizlet.generated.enums.S1;
import com.quizlet.quizletandroid.t;
import io.reactivex.rxjava3.internal.operators.completable.l;
import io.reactivex.rxjava3.internal.operators.maybe.h;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class RootActivity extends AbstractActivityC0055k implements dagger.hilt.internal.b {
    public static final /* synthetic */ int o = 0;
    public com.quizlet.login.authentication.login.a c;
    public volatile dagger.hilt.android.internal.managers.b d;
    public final Object e = new Object();
    public boolean f = false;
    public c0 g;
    public UserInfoCache h;
    public com.quizlet.infra.legacysyncengine.managers.d i;
    public com.quizlet.braze.e j;
    public com.google.firebase.crashlytics.b k;
    public com.google.firebase.crashlytics.internal.settings.b l;
    public com.quizlet.features.notes.a m;
    public t n;

    public RootActivity() {
        addOnContextAvailableListener(new C0054j(this, 25));
    }

    public final void B(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = x().b();
            this.c = aVarB;
            if (aVarB.l()) {
                this.c.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    public final void C(Intent[] intentArr) {
        E.A(p0.h(this), null, null, new b(this, intentArr, null), 3);
    }

    public final void D() {
        if (!isTaskRoot()) {
            finish();
            return;
        }
        UserInfoCache userInfoCache = this.h;
        if (userInfoCache == null) {
            Intrinsics.m("userInfoCache");
            throw null;
        }
        if (!userInfoCache.b()) {
            t tVar = this.n;
            if (tVar != null) {
                startActivityForResult((Intent) tVar.get(), 201);
                return;
            } else {
                Intrinsics.m("introIntentProvider");
                throw null;
            }
        }
        com.google.firebase.crashlytics.b bVar = this.k;
        if (bVar == null) {
            Intrinsics.m("firebaseCrashlytics");
            throw null;
        }
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.i;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        String strValueOf = String.valueOf(dVar.e.getPersonId());
        q qVar = bVar.a;
        qVar.o.a.a(new i(1, qVar, strValueOf));
        Trace traceA = com.google.firebase.perf.b.a("RootActivity_setBrazeUser_trace");
        com.quizlet.infra.legacysyncengine.managers.d dVar2 = this.i;
        if (dVar2 == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        j cachedUserSingle = new j(new h(0, dVar2.a(), c.a), c.b, 1);
        Intrinsics.checkNotNullExpressionValue(cachedUserSingle, "map(...)");
        com.quizlet.braze.e eVar = this.j;
        if (eVar == null) {
            Intrinsics.m("brazeUserManager");
            throw null;
        }
        Intrinsics.checkNotNullParameter(cachedUserSingle, "cachedUserSingle");
        cachedUserSingle.e(new l(new com.quizlet.analytics.marketing.e(eVar, 1), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c));
        traceA.stop();
        C(new Intent[]{D4.a(this, null)});
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return x().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws Resources.NotFoundException {
        Trace traceA = com.google.firebase.perf.b.a("RootActivity_onCreate_trace");
        B(bundle);
        Intrinsics.checkNotNullParameter(this, "<this>");
        (Build.VERSION.SDK_INT >= 31 ? new androidx.core.splashscreen.b(this) : new com.airbnb.lottie.network.d(this)).l();
        c0 c0Var = this.g;
        if (c0Var == null) {
            Intrinsics.m("presenter");
            throw null;
        }
        Intrinsics.checkNotNullParameter(this, "rootView");
        c0Var.g = this;
        com.quizlet.features.notes.a aVar = this.m;
        if (aVar == null) {
            Intrinsics.m("widgetsEventLogger");
            throw null;
        }
        Intent intent = getIntent();
        Intrinsics.checkNotNullExpressionValue(intent, "getIntent(...)");
        aVar.a(intent);
        traceA.stop();
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.c;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() throws PackageManager.NameNotFoundException {
        Trace traceA = com.google.firebase.perf.b.a("RootActivity_onStart_trace");
        super.onStart();
        E.A(p0.h(this), null, null, new a(this, null), 3);
        traceA.stop();
    }

    public final dagger.hilt.android.internal.managers.b x() {
        if (this.d == null) {
            synchronized (this.e) {
                try {
                    if (this.d == null) {
                        this.d = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.d;
    }

    public final void y() {
        FirebaseMessagePayload payload;
        Trace traceA = com.google.firebase.perf.b.a("RootActivity_normalStartLogic_trace");
        if (getIntent().hasExtra("firebasePayload")) {
            payload = (FirebaseMessagePayload) getIntent().getParcelableExtra("firebasePayload");
        } else if (getIntent().hasExtra("data")) {
            Bundle extras = getIntent().getExtras();
            Intrinsics.d(extras);
            String string = extras.getString("data");
            Intrinsics.d(string);
            payload = AbstractC3689o4.h(string);
        } else {
            payload = null;
        }
        if (payload != null) {
            c0 c0Var = this.g;
            if (c0Var == null) {
                Intrinsics.m("presenter");
                throw null;
            }
            Intrinsics.checkNotNullParameter(payload, "payload");
            ((EventLogger) c0Var.c).w(payload);
            if (((com.quizlet.infra.legacysyncengine.managers.d) c0Var.b).e.getPersonId() != payload.getUserId()) {
                RootActivity rootActivity = (RootActivity) c0Var.g;
                if (rootActivity == null) {
                    Intrinsics.m("rootView");
                    throw null;
                }
                rootActivity.D();
            } else {
                S1 type = payload.getType();
                int i = type == null ? -1 : e.a[type.ordinal()];
                if (i == 1) {
                    Long setId = payload.getSetId();
                    if (setId != null) {
                        RootActivity rootActivity2 = (RootActivity) c0Var.g;
                        if (rootActivity2 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity2.z(setId.longValue());
                    } else {
                        RootActivity rootActivity3 = (RootActivity) c0Var.g;
                        if (rootActivity3 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity3.D();
                    }
                } else if (i == 2) {
                    Long folderId = payload.getFolderId();
                    if (folderId != null) {
                        RootActivity rootActivity4 = (RootActivity) c0Var.g;
                        if (rootActivity4 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        long jLongValue = folderId.longValue();
                        Intent intentA = D4.a(rootActivity4, null);
                        String str = FolderActivity.j;
                        rootActivity4.C(new Intent[]{intentA, AbstractC3309z0.b(rootActivity4, jLongValue)});
                    } else {
                        RootActivity rootActivity5 = (RootActivity) c0Var.g;
                        if (rootActivity5 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity5.D();
                    }
                } else if (i == 3) {
                    Long setId2 = payload.getSetId();
                    if (setId2 != null) {
                        RootActivity rootActivity6 = (RootActivity) c0Var.g;
                        if (rootActivity6 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity6.z(setId2.longValue());
                    } else {
                        RootActivity rootActivity7 = (RootActivity) c0Var.g;
                        if (rootActivity7 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity7.D();
                    }
                } else if (i == 4) {
                    EnumC4495k0 destination = payload.getDestination();
                    if (destination != null) {
                        int i2 = e.b[destination.ordinal()];
                        if (i2 == 1) {
                            RootActivity rootActivity8 = (RootActivity) c0Var.g;
                            if (rootActivity8 == null) {
                                Intrinsics.m("rootView");
                                throw null;
                            }
                            rootActivity8.D();
                        } else {
                            if (i2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            RootActivity rootActivity9 = (RootActivity) c0Var.g;
                            if (rootActivity9 == null) {
                                Intrinsics.m("rootView");
                                throw null;
                            }
                            Intent intentA2 = D4.a(rootActivity9, null);
                            Intent intentI = u.i(rootActivity9, m2.b, null, null, null, 28);
                            ArrayList arrayList = new ArrayList();
                            arrayList.add(intentA2);
                            arrayList.add(intentI);
                            int size = arrayList.size();
                            Intent[] intentArr = new Intent[size];
                            if (size != 0) {
                                intentArr[0] = new Intent((Intent) arrayList.get(0)).addFlags(268484608);
                                for (int i3 = 1; i3 < size; i3++) {
                                    intentArr[i3] = new Intent((Intent) arrayList.get(i3));
                                }
                            }
                            Intrinsics.checkNotNullExpressionValue(intentArr, "getIntents(...)");
                            rootActivity9.C(intentArr);
                        }
                    } else {
                        RootActivity rootActivity10 = (RootActivity) c0Var.g;
                        if (rootActivity10 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity10.D();
                    }
                } else if (i != 5) {
                    RootActivity rootActivity11 = (RootActivity) c0Var.g;
                    if (rootActivity11 == null) {
                        Intrinsics.m("rootView");
                        throw null;
                    }
                    rootActivity11.D();
                } else {
                    Long setId3 = payload.getSetId();
                    if (setId3 != null) {
                        RootActivity rootActivity12 = (RootActivity) c0Var.g;
                        if (rootActivity12 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity12.z(setId3.longValue());
                    } else {
                        RootActivity rootActivity13 = (RootActivity) c0Var.g;
                        if (rootActivity13 == null) {
                            Intrinsics.m("rootView");
                            throw null;
                        }
                        rootActivity13.D();
                    }
                }
            }
        } else {
            D();
        }
        traceA.stop();
    }

    public final void z(long j) {
        C(new Intent[]{D4.a(this, null), com.quizlet.features.setpage.e.b(SetPageActivity.h1, this, j, null, null, null, null, false, null, 252)});
    }
}
