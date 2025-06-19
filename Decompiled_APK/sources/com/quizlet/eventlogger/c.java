package com.quizlet.eventlogger;

import android.content.Context;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class c implements Runnable {
    public final /* synthetic */ EventLogBuilder a;
    private final LogRollCompletionListener completionListener;

    public c(EventLogBuilder eventLogBuilder, com.google.firebase.tracing.a aVar) {
        this.a = eventLogBuilder;
        this.completionListener = aVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        EventLogBuilder eventLogBuilder = this.a;
        try {
            EventFileWriter eventFileWriter = eventLogBuilder.mFileWriter;
            Context context = eventLogBuilder.mContext;
            eventFileWriter.getClass();
            EventFileWriter.b(context);
            this.completionListener.a(true);
        } catch (IOException e) {
            timber.log.c.a(e);
            this.completionListener.a(false);
        }
    }
}
