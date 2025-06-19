package com.quizlet.quizletandroid.util;

import android.content.Context;
import com.quizlet.db.data.database.DbSizeHelper;
import com.quizlet.eventlogger.EventLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final Context a;
    public final com.quizlet.quizletandroid.managers.audio.g b;
    public final com.quizlet.quizletandroid.ui.common.images.loading.offline.c c;
    public final DbSizeHelper d;
    public final EventLogger e;
    public final io.reactivex.rxjava3.core.o f;

    public n(Context context, com.quizlet.quizletandroid.managers.audio.g audioResourceStore, com.quizlet.quizletandroid.ui.common.images.loading.offline.c imageResourceStore, DbSizeHelper dbSizeHelper, EventLogger eventLogger, io.reactivex.rxjava3.core.o ioScheduler) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(audioResourceStore, "audioResourceStore");
        Intrinsics.checkNotNullParameter(imageResourceStore, "imageResourceStore");
        Intrinsics.checkNotNullParameter(dbSizeHelper, "dbSizeHelper");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
        this.a = context;
        this.b = audioResourceStore;
        this.c = imageResourceStore;
        this.d = dbSizeHelper;
        this.e = eventLogger;
        this.f = ioScheduler;
    }
}
