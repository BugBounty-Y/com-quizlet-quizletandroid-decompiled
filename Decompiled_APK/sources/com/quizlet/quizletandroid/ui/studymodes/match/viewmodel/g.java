package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import androidx.compose.foundation.text.input.internal.u;
import androidx.compose.ui.node.V;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.facebook.C1544a;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.data.repository.metering.j;
import com.quizlet.features.match.data.AbstractC4368y;
import com.quizlet.features.match.data.d0;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends com.quizlet.viewmodel.b implements InterfaceC1250k {
    public final androidx.work.impl.model.c c;
    public final C1544a d;
    public final com.quizlet.quizletandroid.audio.players.c e;
    public final com.quizlet.features.match.audio.a f;
    public final com.quizlet.data.repository.user.a g;
    public final com.quizlet.features.infra.basestudy.manager.f h;
    public final j i;
    public final com.quizlet.features.match.logging.b j;
    public final com.quizlet.quizletandroid.ui.studymodes.match.managers.a k;
    public final com.quizlet.viewmodel.livedata.b l;
    public final Y m;
    public final X n;
    public final X o;
    public final X p;
    public final X q;
    public final Y r;
    public final X s;
    public final X t;
    public final X u;
    public final Y v;
    public final Y w;
    public InterfaceC5025j0 x;

    public g(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, u dataProviderFactory, com.quizlet.data.repository.studysetwithcreator.d matchShareSetManagerFactory, com.quizlet.data.repository.course.membership.c loggerFactory, androidx.work.impl.model.c userProps, C1544a matchMusicSharedPreferenceManager, com.quizlet.quizletandroid.audio.players.c audioPlayer, com.quizlet.features.match.audio.a audioResourceRetriever, com.quizlet.data.repository.user.a enablePrebidSdkFeature) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(dataProviderFactory, "dataProviderFactory");
        Intrinsics.checkNotNullParameter(matchShareSetManagerFactory, "matchShareSetManagerFactory");
        Intrinsics.checkNotNullParameter(loggerFactory, "loggerFactory");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(matchMusicSharedPreferenceManager, "matchMusicSharedPreferenceManager");
        Intrinsics.checkNotNullParameter(audioPlayer, "audioPlayer");
        Intrinsics.checkNotNullParameter(audioResourceRetriever, "audioResourceRetriever");
        Intrinsics.checkNotNullParameter(enablePrebidSdkFeature, "enablePrebidSdkFeature");
        this.c = userProps;
        this.d = matchMusicSharedPreferenceManager;
        this.e = audioPlayer;
        this.f = audioResourceRetriever;
        this.g = enablePrebidSdkFeature;
        this.h = studyModeManagerFactory.a(savedStateHandle);
        this.i = dataProviderFactory.d(savedStateHandle);
        this.j = loggerFactory.f(savedStateHandle);
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        s sVarC = ((V) matchShareSetManagerFactory.c).c(savedStateHandle);
        this.k = new com.quizlet.quizletandroid.ui.studymodes.match.managers.a(((com.quizlet.features.infra.basestudy.manager.a) matchShareSetManagerFactory.d).a(savedStateHandle), (com.quizlet.infra.legacysyncengine.managers.d) matchShareSetManagerFactory.a, sVarC, (com.quizlet.quizletandroid.deeplinks.a) matchShareSetManagerFactory.b);
        com.quizlet.viewmodel.livedata.b bVar = new com.quizlet.viewmodel.livedata.b();
        this.l = bVar;
        this.m = new Y();
        this.n = new X(1);
        this.o = new X(1);
        this.p = new X(1);
        this.q = new X(1);
        this.r = new Y();
        this.s = new X(1);
        this.t = new X(1);
        this.u = new X(1);
        Y y = new Y();
        this.v = y;
        this.w = new Y(Boolean.FALSE);
        bVar.n();
        y.l(Boolean.valueOf(matchMusicSharedPreferenceManager.a.getBoolean("PREF_MATCH_PLAY_AUDIO", true)));
        E.A(p0.j(this), null, null, new b(this, null), 3);
        E.A(p0.j(this), null, null, new e(this, null), 3);
    }

    public final void B(AbstractC4368y abstractC4368y) {
        Boolean bool = (Boolean) this.v.d();
        if (bool != null ? bool.booleanValue() : true) {
            InterfaceC5025j0 interfaceC5025j0 = this.x;
            if (interfaceC5025j0 != null) {
                interfaceC5025j0.j(null);
            }
            this.x = E.A(p0.j(this), com.facebook.appevents.iap.u.d(), null, new c(abstractC4368y, this, null), 2);
        }
    }

    public final void C(boolean z) {
        this.l.n();
        String string = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        com.quizlet.features.match.data.V v = new com.quizlet.features.match.data.V(z, string);
        this.m.j(v);
        B(v);
    }

    public final void D() {
        E.A(p0.j(this), null, null, new f(this, null), 3);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        AbstractC4368y abstractC4368y = (AbstractC4368y) this.m.d();
        if (abstractC4368y == null || abstractC4368y.equals(d0.a)) {
            return;
        }
        B(abstractC4368y);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStop(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        D();
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        j jVar = this.i;
        ((AtomicReference) jVar.c).dispose();
        ((com.quizlet.features.infra.basestudy.manager.f) jVar.a).x.f();
    }
}
