package com.android.billingclient.api;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Messenger;
import androidx.lifecycle.X;
import com.google.android.gms.internal.play_billing.AbstractBinderC3797g;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C3794f;
import com.google.android.gms.internal.play_billing.InterfaceC3800h;
import com.google.android.gms.internal.play_billing.M1;
import com.google.firebase.sessions.b0;
import com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingDeque;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class u implements ServiceConnection {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ u(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        InterfaceC3800h c3794f = null;
        switch (this.a) {
            case 0:
                AbstractC3819n0.e("BillingClientTesting", "Billing Override Service connected.");
                v vVar = (v) this.b;
                int i = AbstractBinderC3797g.b;
                if (iBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.apps.play.billingtestcompanion.aidl.IBillingOverrideService");
                    c3794f = iInterfaceQueryLocalInterface instanceof InterfaceC3800h ? (InterfaceC3800h) iInterfaceQueryLocalInterface : new C3794f(iBinder, "com.google.android.apps.play.billingtestcompanion.aidl.IBillingOverrideService", 6);
                }
                vVar.H = c3794f;
                ((v) this.b).G = 2;
                v vVar2 = (v) this.b;
                vVar2.getClass();
                M1 m1D = y.d(26);
                Objects.requireNonNull(m1D, "ApiSuccess should not be null");
                vVar2.g.D(m1D);
                return;
            case 1:
                com.google.android.play.core.review.internal.j jVar = (com.google.android.play.core.review.internal.j) this.b;
                jVar.b.a("ServiceConnectionImpl.onServiceConnected(%s)", componentName);
                jVar.a().post(new com.google.android.play.core.review.internal.i(this, iBinder));
                return;
            case 2:
                com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) this.b;
                ((LinkedBlockingDeque) aVar.c).size();
                aVar.b = new Messenger(iBinder);
                ArrayList arrayList = new ArrayList();
                ((LinkedBlockingDeque) aVar.c).drainTo(arrayList);
                E.A(E.c((CoroutineContext) aVar.a), null, null, new b0(aVar, arrayList, null), 3);
                return;
            default:
                Intrinsics.e(iBinder, "null cannot be cast to non-null type com.quizlet.features.flashcards.autoplay.AutoplayBinder");
                com.quizlet.features.flashcards.autoplay.a aVar2 = (com.quizlet.features.flashcards.autoplay.a) iBinder;
                FlashcardsAutoplayService flashcardsAutoplayService = aVar2.a;
                com.quizlet.features.flashcards.autoplay.o oVar = (com.quizlet.features.flashcards.autoplay.o) this.b;
                if (flashcardsAutoplayService != null) {
                    X liveData = oVar.a;
                    Intrinsics.checkNotNullParameter(liveData, "liveData");
                    flashcardsAutoplayService.i = liveData;
                }
                FlashcardsAutoplayService flashcardsAutoplayService2 = aVar2.a;
                if (flashcardsAutoplayService2 != null) {
                    com.quizlet.features.flashcards.autoplay.q qVar = oVar.b;
                    if (qVar == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    flashcardsAutoplayService2.h(qVar);
                }
                oVar.c = aVar2.a;
                timber.log.c.a.g("Service connection connected", new Object[0]);
                return;
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        switch (this.a) {
            case 0:
                AbstractC3819n0.f("BillingClientTesting", "Billing Override Service disconnected.");
                ((v) this.b).H = null;
                ((v) this.b).G = 0;
                break;
            case 1:
                com.google.android.play.core.review.internal.j jVar = (com.google.android.play.core.review.internal.j) this.b;
                jVar.b.a("ServiceConnectionImpl.onServiceDisconnected(%s)", componentName);
                jVar.a().post(new com.google.android.play.core.review.internal.h(this, 1));
                break;
            case 2:
                com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) this.b;
                aVar.b = null;
                aVar.getClass();
                break;
            default:
                timber.log.c.a.g("Service connection disconnected", new Object[0]);
                com.quizlet.features.flashcards.autoplay.o oVar = (com.quizlet.features.flashcards.autoplay.o) this.b;
                oVar.c = null;
                oVar.b = null;
                break;
        }
    }
}
