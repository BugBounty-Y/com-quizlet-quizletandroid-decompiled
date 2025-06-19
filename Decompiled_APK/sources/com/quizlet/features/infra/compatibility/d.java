package com.quizlet.features.infra.compatibility;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.CompatibilityCheckDataWrapper;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import java.util.List;
import javax.net.ssl.SSLException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import retrofit2.HttpException;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, boolean z, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objJ;
        List responses;
        ApiResponse apiResponse;
        CompatibilityCheckDataWrapper compatibilityCheckDataWrapper;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        try {
        } catch (Throwable th) {
            this.j = 2;
            eVar.getClass();
            if (th instanceof SSLException) {
                SSLException sSLException = (SSLException) th;
                if (this.l) {
                    timber.log.c.a.f(sSLException, "Irrecoverable ApiCompatCheck SSLException thrown", new Object[0]);
                    objJ = Unit.a;
                } else {
                    timber.log.a aVar2 = timber.log.c.a;
                    aVar2.q(sSLException, "SSLHandshakeException thrown. Proceeding to SslProviderInstaller", new Object[0]);
                    Context context = (Context) eVar.d;
                    Intrinsics.checkNotNullParameter(context, "context");
                    try {
                        aVar2.o("Attempting to install SSL Provider", new Object[0]);
                        com.google.android.gms.security.a.a(context);
                    } catch (GooglePlayServicesNotAvailableException e) {
                        timber.log.c.a.p(e);
                    } catch (GooglePlayServicesRepairableException e2) {
                        timber.log.c.a.p(e2);
                        GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
                        int i2 = e2.a;
                        Intent intentB = googleApiAvailability.b(context, "n", i2);
                        googleApiAvailability.g(context, i2, intentB == null ? null : PendingIntent.getActivity(context, 0, intentB, 201326592));
                    }
                    objJ = E.J((AbstractC5040y) eVar.e, new d(eVar, true, null), this);
                    if (objJ != kotlin.coroutines.intrinsics.a.a) {
                        objJ = Unit.a;
                    }
                }
                if (objJ != kotlin.coroutines.intrinsics.a.a) {
                    objJ = Unit.a;
                }
            } else {
                if (th instanceof HttpException) {
                    HttpException httpException = (HttpException) th;
                    int i3 = httpException.a;
                    if (400 > i3 || i3 >= 500) {
                        timber.log.c.a.q(httpException, "ApiCompatCheck netException thrown", new Object[0]);
                    } else {
                        timber.log.c.a.f(httpException, "ApiCompatCheck netException thrown", new Object[0]);
                    }
                }
                objJ = Unit.a;
            }
            if (objJ != aVar) {
                return null;
            }
        }
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            obj = e.a(eVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                return null;
            }
            Z.e(obj);
        }
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) ((K) obj).b;
        return e.b(eVar, (apiThreeWrapper == null || (responses = apiThreeWrapper.getResponses()) == null || (apiResponse = (ApiResponse) CollectionsKt.firstOrNull(responses)) == null || (compatibilityCheckDataWrapper = (CompatibilityCheckDataWrapper) apiResponse.getDataWrapper()) == null) ? null : compatibilityCheckDataWrapper.getCompatibilityCheck());
    }
}
