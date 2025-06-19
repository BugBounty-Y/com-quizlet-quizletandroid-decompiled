package com.quizlet.quizletandroid.ui.usersettings.viewmodels;

import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.infra.legacysyncengine.net.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class c extends com.quizlet.viewmodel.b {
    public final m0 c;
    public final d d;
    public final f e;
    public final Y f;

    public c(m0 savedStateHandle, d loggedInUserManager, f syncDispatcher) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        this.c = savedStateHandle;
        this.d = loggedInUserManager;
        this.e = syncDispatcher;
        savedStateHandle.c(savedStateHandle.a("ARG_PROFILE_IMAGE_ID"), DBUserFields.Names.PROFILE_IMAGE_ID);
        this.f = new Y();
    }
}
