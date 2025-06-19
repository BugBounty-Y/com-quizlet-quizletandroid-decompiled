package com.quizlet.comscore;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import com.comscore.Analytics;
import com.comscore.Configuration;
import com.comscore.PublisherConfiguration;
import com.google.firebase.perf.b;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.data.model.C4135i0;
import com.quizlet.features.flashcards.helpers.d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ u k;
    public final /* synthetic */ ComscoreInitializer l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(u uVar, ComscoreInitializer comscoreInitializer, Context context, h hVar) {
        super(2, hVar);
        this.k = uVar;
        this.l = comscoreInitializer;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r5v5, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            d dVar = new d(((com.quizlet.usecase.a) this.k.o.get()).a, 5);
            this.j = 1;
            obj = e0.p(dVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (!((C4135i0) obj).w) {
            this.l.getClass();
            Trace traceA = b.a("ComscoreInitializer_initComscore");
            PublisherConfiguration.Builder builder = new PublisherConfiguration.Builder();
            Context context = this.m;
            PublisherConfiguration publisherConfigurationBuild = builder.publisherId(context.getString(R.string.com_score_publish_id)).build();
            Configuration configuration = Analytics.getConfiguration();
            configuration.addClient(publisherConfigurationBuild);
            configuration.enableChildDirectedApplicationMode();
            configuration.setApplicationName(context.getString(R.string.app_name));
            Analytics.start(context);
            traceA.stop();
        }
        return Unit.a;
    }
}
