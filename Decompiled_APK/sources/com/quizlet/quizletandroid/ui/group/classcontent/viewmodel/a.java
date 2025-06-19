package com.quizlet.quizletandroid.ui.group.classcontent.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.m0;
import com.quizlet.quizletandroid.util.o;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends com.quizlet.viewmodel.a {
    public final com.quizlet.local.ormlite.models.term.b d;
    public final o e;
    public final com.quizlet.offline.managers.b f;
    public final com.quizlet.data.interactor.achievements.f g;
    public final com.quizlet.shared.usecase.srs.a h;
    public final androidx.work.impl.model.c i;
    public final io.reactivex.rxjava3.core.o j;
    public final com.quizlet.time.b k;
    public final com.quizlet.viewmodel.livedata.b l;
    public final X m;
    public final X n;
    public final long o;
    public final com.quizlet.quizletandroid.config.features.properties.b p;

    public a(m0 savedStateHandle, com.quizlet.local.ormlite.models.term.b dataManager, o timestampFormatter, com.quizlet.offline.managers.b offlineStateManager, com.quizlet.data.interactor.achievements.f addToClassPermissionHelper, com.quizlet.shared.usecase.srs.a addToClassFeature, com.quizlet.quizletandroid.ui.group.data.b groupMembershipPropertiesFactory, androidx.work.impl.model.c userProperties, io.reactivex.rxjava3.core.o computationScheduler) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataManager, "dataManager");
        Intrinsics.checkNotNullParameter(timestampFormatter, "timestampFormatter");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        Intrinsics.checkNotNullParameter(addToClassPermissionHelper, "addToClassPermissionHelper");
        Intrinsics.checkNotNullParameter(addToClassFeature, "addToClassFeature");
        Intrinsics.checkNotNullParameter(groupMembershipPropertiesFactory, "groupMembershipPropertiesFactory");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(computationScheduler, "computationScheduler");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.d = dataManager;
        this.e = timestampFormatter;
        this.f = offlineStateManager;
        this.g = addToClassPermissionHelper;
        this.h = addToClassFeature;
        this.i = userProperties;
        this.j = computationScheduler;
        this.k = timeProvider;
        com.quizlet.viewmodel.livedata.b bVar = new com.quizlet.viewmodel.livedata.b();
        this.l = bVar;
        this.m = new X(1);
        this.n = new X(1);
        Object objA = savedStateHandle.a("KEY_GROUP_CLASS_ID");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        long jLongValue = ((Number) objA).longValue();
        this.o = jLongValue;
        this.p = new com.quizlet.quizletandroid.config.features.properties.b(jLongValue, groupMembershipPropertiesFactory.b, groupMembershipPropertiesFactory.a);
        bVar.n();
    }

    public final void B(Object obj) {
        com.quizlet.quizletandroid.ui.group.classcontent.models.a item = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        if (item instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.c) {
            this.m.j(new j(((com.quizlet.quizletandroid.ui.group.classcontent.models.c) item).a));
            return;
        }
        if (!(item instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.d)) {
            if (!(item instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.e)) {
                throw new NoWhenBranchMatchedException();
            }
            return;
        }
        com.quizlet.quizletandroid.ui.group.classcontent.models.d dVar = (com.quizlet.quizletandroid.ui.group.classcontent.models.d) item;
        com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar = dVar.b;
        io.reactivex.rxjava3.internal.observers.e eVarI = ((com.quizlet.offline.managers.i) this.f).a(dVar.a, bVar != null ? bVar.d : false).i(new com.quizlet.billing.manager.b(11, this, dVar), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }
}
