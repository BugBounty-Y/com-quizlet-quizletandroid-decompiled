package com.quizlet.features.notes;

import android.content.Intent;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
            default:
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                this.a = eventLogger;
                break;
        }
    }

    public void a(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        String widgetUrl = intent.getStringExtra("quizletWidgetUrlKey");
        if (widgetUrl != null) {
            Intrinsics.checkNotNullParameter("engagement_widget_tapped", "event");
            Intrinsics.checkNotNullParameter(widgetUrl, "widgetUrl");
            EventLoggerExt.a(this.a, "engagement_widget_tapped", new com.quizlet.library.logging.a(widgetUrl, 5));
        }
    }

    public void b(List deleted, List added) {
        EventLogger eventLogger;
        Intrinsics.checkNotNullParameter(deleted, "deleted");
        Intrinsics.checkNotNullParameter(added, "added");
        Iterator it2 = deleted.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            eventLogger = this.a;
            if (!zHasNext) {
                break;
            }
            DBGroupSet dBGroupSet = (DBGroupSet) it2.next();
            EventLoggerExt.c(eventLogger, new com.quizlet.quizletandroid.ui.group.classcontent.logging.a(dBGroupSet.getClassId(), dBGroupSet.getSetId(), 0));
        }
        Iterator it3 = added.iterator();
        while (it3.hasNext()) {
            DBGroupSet dBGroupSet2 = (DBGroupSet) it3.next();
            EventLoggerExt.c(eventLogger, new com.quizlet.quizletandroid.ui.group.classcontent.logging.a(dBGroupSet2.getClassId(), dBGroupSet2.getSetId(), 1));
        }
    }
}
